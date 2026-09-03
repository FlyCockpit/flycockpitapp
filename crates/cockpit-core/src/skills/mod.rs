//! Skill discovery, parsing, and body assembly.
//!
//! A *skill* is a `<dir>/<name>/SKILL.md` file: YAML frontmatter
//! (`name`, `description`, optional `model`, plus the Claude-parity
//! invocation flags `disable-model-invocation` / `user-invocable` and a
//! forward-compat catch-all for the rest of Claude's schema) plus a
//! markdown body. The
//! `(name, description)` catalog is cheap and surfaced for progressive
//! disclosure (GOALS §10) — bodies load only when a skill is selected by
//! the utility model (auto path) or invoked by name via the `skill` tool
//! (manual path).
//!
//! Scan directories come from [`crate::config::extended::SkillsConfig`].
//! The list ships pre-seeded on a fresh install
//! ([`crate::config::extended::SEEDED_SCAN_DIRS`]: `~/.agents/skills` +
//! `./.agents/skills`) but is otherwise authoritative — an empty list
//! scans nothing (no implicit fallback). Entries support `~` home
//! expansion, `$VAR` references (via [`crate::envref`]), and relative
//! paths resolved against cwd; with `SkillsConfig::ancestor_walk` enabled
//! each relative entry also expands to every ancestor up to the git
//! worktree root. Non-existent directories are silently ignored; a
//! malformed `SKILL.md` is skipped with a logged warning and never aborts
//! the scan.
//!
//! ## `!`-command processing (Claude vs Codex mode)
//!
//! A body may embed Claude-style inline `` !`command` `` directives.
//! [`render_body`] resolves them according to the auto-`!` toggle:
//!   - **Claude mode (enabled):** run each command, replace the inline
//!     directive with the command's stdout. Output is routed through
//!     [`crate::redact::RedactionTable::scrub`] plus the novel-secret pass
//!     (`RedactionTable::scrub_novel_command_output_secrets`, covering
//!     secret-shaped values first surfaced by the command itself —
//!     non-bypassable, GOALS §7) before it enters context. A nonzero
//!     exit / spawn failure injects a clear inline error marker rather
//!     than crashing the turn.
//!   - **Codex mode (disabled, the default):** the `` !`command` ``
//!     directive is left verbatim — the model sees the literal text and
//!     the command never runs.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::extended::SkillsConfig;
use crate::redact::RedactionTable;

pub mod auto_select;
pub mod curator;
pub mod manage;

const TRANSCRIPT_SOURCE: &str =
    "the reusable workflow we just completed in this conversation transcript";
const MAX_MARKDOWN_BYTES: u64 = 1024 * 1024;
const MAX_CATALOG_DESCRIPTION_CHARS: usize = 60;
const MAX_MANAGED_SKILL_CHARS: usize = 100_000;
const SUPPORT_DIRS: [&str; 4] = ["references", "templates", "scripts", "assets"];
pub const MODEL_SKILL_CATALOG_LABEL: &str = "Available skills";
static CATALOG_GENERATION: AtomicU64 = AtomicU64::new(0);
static DISCOVERY_WALK_CALLS: AtomicU64 = AtomicU64::new(0);
static CATALOG_CACHE: OnceLock<Mutex<HashMap<Vec<PathBuf>, CatalogCacheEntry>>> = OnceLock::new();

pub fn subject_from_parts(parts: &[String]) -> String {
    let subject = parts.join(" ");
    let subject = subject.trim();
    if subject.is_empty() {
        TRANSCRIPT_SOURCE.to_string()
    } else {
        subject.to_string()
    }
}

/// Compose the single ordinary user turn shared by the slash and CLI forms.
pub fn build_learn_prompt(subject: &str) -> String {
    let subject = subject.trim();
    let subject = if subject.is_empty() {
        TRANSCRIPT_SOURCE
    } else {
        subject
    };
    format!(
        "Create a reusable Agent Skill from the following source request:\n\n\
         <learn-source>\n{subject}\n</learn-source>\n\n\
         This is a user-initiated `/learn` turn. Work through the normal live-agent flow and \
         save the finished package with the `skill_manage` tool so its validation, optional \
         write approval, and foreground provenance apply. If this frame does not expose \
         `skill_manage`, hand off to the Build primary before saving. Do not write SKILL.md \
         directly.\n\n\
         Gather evidence before authoring: use read/search for local paths, web fetch/search \
         for URLs, the current conversation transcript for a just-completed workflow, and \
         the supplied text for pasted steps. Multiple sources normally produce one skill \
         unless the user explicitly asks for more. Do not guess missing facts.\n\n\
         House authoring rules:\n\
         - Choose a conformant lowercase skill name and a concrete description of at most 60 characters.\n\
         - Use these body sections in this order: `## When to Use`, `## Procedure`, `## Pitfalls`, `## Verification`.\n\
         - Frame actions in terms of Cockpit's available tools and ordinary shell commands.\n\
         - Never invent commands, flags, paths, APIs, or verification results; confirm them from the sources.\n\
         - Keep the procedure concise, actionable, and reusable rather than narrating this conversation.\n\
         - Save through `skill_manage` and report the created skill name and source evidence when done."
    )
}

#[derive(Clone)]
struct CatalogCacheEntry {
    skills: Vec<Skill>,
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn reset_discovery_walk_call_count() {
    DISCOVERY_WALK_CALLS.store(0, Ordering::Relaxed);
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn discovery_walk_call_count() -> u64 {
    DISCOVERY_WALK_CALLS.load(Ordering::Relaxed)
}

/// Monotonic invalidation generation for consumers that retain a discovered
/// skill catalog between turns. The loader itself remains filesystem-live;
/// cached UI/index projections can cheaply detect a successful mutation.
#[cfg_attr(not(test), allow(dead_code))]
pub fn catalog_generation() -> u64 {
    CATALOG_GENERATION.load(Ordering::Relaxed)
}

pub fn invalidate_catalog_cache(cwd: &Path, cfg: &SkillsConfig) -> u64 {
    let generation = CATALOG_GENERATION.fetch_add(1, Ordering::Relaxed) + 1;
    if let Some(cache) = CATALOG_CACHE.get() {
        cache.lock().unwrap().remove(&resolve_scan_dirs(cwd, cfg));
    }
    generation
}

#[cfg(test)]
pub(crate) fn catalog_cache_contains(cwd: &Path, cfg: &SkillsConfig) -> bool {
    let dirs = resolve_scan_dirs(cwd, cfg);
    CATALOG_CACHE
        .get()
        .is_some_and(|cache| cache.lock().unwrap().contains_key(&dirs))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillMetadata {
    #[serde(default)]
    pub hermes: HermesMetadata,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HermesMetadata {
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub requires_toolsets: Vec<String>,
    #[serde(default)]
    pub fallback_for_toolsets: Vec<String>,
    #[serde(default)]
    pub requires_tools: Vec<String>,
    #[serde(default)]
    pub fallback_for_tools: Vec<String>,
    /// Hermes specifies `platforms` at top level. Accept it here too for
    /// packages authored against older examples.
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub config: Vec<HermesConfigSetting>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HermesConfigSetting {
    pub key: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default: Option<serde_yaml::Value>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequiredEnvironmentVariable {
    pub name: String,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub help: Option<String>,
    #[serde(default)]
    pub required_for: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillFrontmatter {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub platforms: Vec<String>,
    #[serde(default)]
    pub metadata: SkillMetadata,
    #[serde(default)]
    pub required_environment_variables: Vec<RequiredEnvironmentVariable>,
    #[serde(default)]
    pub model: Option<String>,
    /// Claude Code parity: when `true` the skill is user-only — the
    /// utility-model auto-selector never sees its description and never
    /// auto-injects it. Default `false` (model-invokable).
    #[serde(rename = "disable-model-invocation", default)]
    pub disable_model_invocation: bool,
    /// Claude Code parity: when `false` the skill is model-only — hidden
    /// from the user's `/` slash menu but still eligible for
    /// auto-injection. Default `true` (user-invocable).
    #[serde(rename = "user-invocable", default = "default_true")]
    pub user_invocable: bool,
    /// Forward-compat catch-all: every other Claude frontmatter field
    /// (`when_to_use`, `paths`, `allowed-tools`, `disallowed-tools`,
    /// `context`, `agent`, `hooks`, `effort`, `argument-hint`,
    /// `arguments`, `shell`, …) parses cleanly here instead of erroring,
    /// so adopting more of the schema later is non-breaking. Behavior for
    /// these is deliberately not implemented yet.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

fn default_true() -> bool {
    true
}

impl Default for SkillFrontmatter {
    /// The permissive defaults: a nameless skill that is both
    /// user-invocable and model-invokable. Used as a base for test
    /// construction and for `..Default::default()` field spreads; the
    /// production path always populates `name`/`description` from parsed
    /// frontmatter.
    fn default() -> Self {
        Self {
            name: String::new(),
            description: String::new(),
            version: None,
            platforms: Vec::new(),
            metadata: SkillMetadata::default(),
            required_environment_variables: Vec::new(),
            model: None,
            disable_model_invocation: false,
            user_invocable: true,
            extra: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Skill {
    pub frontmatter: SkillFrontmatter,
    pub source: PathBuf,
}

pub fn package_root(skill: &Skill) -> &Path {
    skill.source.parent().unwrap_or(&skill.source)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillPackageTarget {
    pub package_root: PathBuf,
    pub name: String,
    pub is_manifest: bool,
    pub relative_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillPackageWriteValidation {
    pub name: String,
    pub package_root: PathBuf,
    pub is_manifest: bool,
}

impl SkillPackageWriteValidation {
    pub fn confirmation_note(&self) -> String {
        let kind = if self.is_manifest {
            "manifest"
        } else {
            "support file"
        };
        format!(
            "\n[skill] validated {} ({kind}); catalog refreshed",
            self.name
        )
    }
}

pub fn package_target_for_path(
    path: &Path,
    cwd: &Path,
    cfg: &SkillsConfig,
) -> Option<SkillPackageTarget> {
    package_target_for_path_with_skill(path, cwd, cfg).map(|(target, _)| target)
}

pub fn validate_skill_package_write(
    path: &Path,
    cwd: &Path,
    cfg: &SkillsConfig,
    content: &str,
) -> Result<Option<SkillPackageWriteValidation>> {
    let Some((target, skill)) = package_target_for_path_with_skill(path, cwd, cfg) else {
        return Ok(None);
    };
    crate::skills::manage::ensure_plain_write_allowed(&skill, &target.package_root)?;
    ensure_no_skill_symlink(&target)?;
    if target.is_manifest {
        validate_managed_skill_contents(content, &target.name)?;
    } else {
        validate_support_relative(&target.relative_path)?;
        if content.chars().count() > MAX_MANAGED_SKILL_CHARS {
            anyhow::bail!("support file exceeds {MAX_MANAGED_SKILL_CHARS} character limit");
        }
    }
    Ok(Some(SkillPackageWriteValidation {
        name: target.name,
        package_root: target.package_root,
        is_manifest: target.is_manifest,
    }))
}

pub fn validate_skill_package_write_for_paths(
    requested_path: &Path,
    effective_path: &Path,
    cwd: &Path,
    cfg: &SkillsConfig,
    content: &str,
) -> Result<Option<SkillPackageWriteValidation>> {
    let contains_parent_traversal = requested_path
        .components()
        .any(|component| component == std::path::Component::ParentDir);
    let requested_target = package_target_for_path_with_skill(requested_path, cwd, cfg);
    if contains_parent_traversal {
        let effective_target = package_target_for_path_with_skill(effective_path, cwd, cfg);
        let raw_absolute = if requested_path.is_absolute() {
            requested_path.to_path_buf()
        } else {
            cwd.join(requested_path)
        };
        let begins_in_scan_dir = resolve_scan_dirs(cwd, cfg)
            .iter()
            .any(|scan_dir| raw_absolute.starts_with(scan_dir));
        if begins_in_scan_dir || requested_target.is_some() || effective_target.is_some() {
            anyhow::bail!("skill package writes cannot contain parent traversal segments");
        }
    }

    if let Some((target, _)) = requested_target {
        ensure_no_skill_symlink(&target)?;
    }
    validate_skill_package_write(effective_path, cwd, cfg, content)
}

fn package_target_for_path_with_skill(
    path: &Path,
    cwd: &Path,
    cfg: &SkillsConfig,
) -> Option<(SkillPackageTarget, Skill)> {
    let path = lexical_absolute_against(path, cwd);
    let scan_dirs = resolve_scan_dirs(cwd, cfg);
    if !scan_dirs
        .iter()
        .map(|dir| lexical_absolute_against(dir, cwd))
        .any(|dir| path.starts_with(&dir) && path != dir)
    {
        return None;
    }
    let skills = discover(cwd, cfg).ok()?;
    for skill in skills {
        let package_root = lexical_absolute_against(package_root(&skill), cwd);
        if !path.starts_with(&package_root) || path == package_root {
            continue;
        }
        let name = package_root
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)?;
        let relative_path = path.strip_prefix(&package_root).ok()?.to_path_buf();
        let is_manifest = relative_path == Path::new("SKILL.md");
        return Some((
            SkillPackageTarget {
                package_root,
                name,
                is_manifest,
                relative_path,
            },
            skill,
        ));
    }
    None
}

fn ensure_no_skill_symlink(target: &SkillPackageTarget) -> Result<()> {
    if std::fs::symlink_metadata(&target.package_root)
        .with_context(|| format!("checking skill package {}", target.package_root.display()))?
        .file_type()
        .is_symlink()
    {
        anyhow::bail!("skill package may not be a symlink");
    }
    let mut cursor = target.package_root.clone();
    let mut components = target.relative_path.components().peekable();
    while let Some(component) = components.next() {
        let std::path::Component::Normal(segment) = component else {
            anyhow::bail!("skill package path may not contain traversal components");
        };
        cursor.push(segment);
        match std::fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                anyhow::bail!("skill package path may not traverse symlinks");
            }
            Ok(metadata) if components.peek().is_some() && !metadata.is_dir() => {
                anyhow::bail!("skill support file parent is not a directory");
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("checking {}", cursor.display()));
            }
        }
    }
    Ok(())
}

fn lexical_absolute_against(path: &Path, cwd: &Path) -> PathBuf {
    let lexical_cwd = lexical_normalize(cwd);
    // Canonicalize only the workspace root, then append the requested path
    // lexically. On macOS, `/var` is an alias for `/private/var`; resolving
    // the root keeps a tempdir-based workspace and the manifest discovered
    // beneath it in the same namespace. Do not canonicalize the requested
    // path itself: that could follow a package-file symlink before the
    // managed-skill symlink guard has a chance to reject it.
    let cwd = cwd.canonicalize().unwrap_or_else(|_| lexical_cwd.clone());
    let absolute = if path.is_absolute() {
        let path = lexical_normalize(path);
        path.strip_prefix(&lexical_cwd)
            .map(|relative| cwd.join(relative))
            .unwrap_or(path)
    } else {
        cwd.join(path)
    };
    lexical_normalize(&absolute)
}

/// Capabilities used to filter conditional Hermes skills for one live agent
/// session. Toolsets are derived from Cockpit's concrete tool registry, so
/// activation follows the surface the model can actually call.
#[derive(Debug, Clone, Default)]
pub struct ActivationContext {
    pub tools: HashSet<String>,
    pub toolsets: HashSet<String>,
    pub platform: String,
}

impl ActivationContext {
    pub fn from_tool_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        let tools: HashSet<String> = names.into_iter().map(str::to_string).collect();
        let mut toolsets = HashSet::new();
        for tool in &tools {
            toolsets.insert(tool.clone());
            if tool.starts_with("web") {
                toolsets.insert("web".to_string());
            }
            if tool.starts_with("browser") {
                toolsets.insert("browser".to_string());
            }
        }
        if tools.contains("bash") {
            toolsets.insert("terminal".to_string());
        }
        if tools.contains("read") || tools.contains("grep") || tools.contains("glob") {
            toolsets.insert("files".to_string());
        }
        if tools.contains("mcp") {
            toolsets.insert("mcp".to_string());
        }
        Self {
            tools,
            toolsets,
            platform: current_platform().to_string(),
        }
    }
}

fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        std::env::consts::OS
    }
}

/// Discover every skill reachable from `cwd` under the configured scan
/// directories. Malformed/missing frontmatter skips that skill with a
/// logged warning; a non-existent directory is silently ignored. Results
/// are de-duplicated by skill `name` keeping the first occurrence — the
/// scan-dir order is the precedence order.
pub fn discover(cwd: &Path, cfg: &SkillsConfig) -> Result<Vec<Skill>> {
    let dirs = resolve_scan_dirs(cwd, cfg);
    let cache = CATALOG_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(entry) = cache.lock().unwrap().get(&dirs) {
        return Ok(entry.skills.clone());
    }
    let skills = discover_uncached(&dirs);

    cache.lock().unwrap().insert(
        dirs,
        CatalogCacheEntry {
            skills: skills.clone(),
        },
    );
    Ok(skills)
}

fn discover_uncached(dirs: &[PathBuf]) -> Vec<Skill> {
    let manifests: Vec<PathBuf> = dirs.iter().flat_map(|dir| manifests_under(dir)).collect();
    let mut skills = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for manifest in manifests {
        match parse_skill(&manifest) {
            Ok(skill) if seen.insert(skill.frontmatter.name.clone()) => skills.push(skill),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(path = %manifest.display(), %error, "skipping malformed SKILL.md");
            }
        }
    }
    skills
}

/// Return every package manifest beneath one configured root in deterministic
/// path order. Category directories used by Hermes are traversed recursively;
/// once a package manifest is found its support directories are not searched
/// for nested packages. Canonical-root checks plus a visited set prevent
/// symlink escapes and loops.
fn manifests_under(root: &Path) -> Vec<PathBuf> {
    DISCOVERY_WALK_CALLS.fetch_add(1, Ordering::Relaxed);
    let Ok(root) = root.canonicalize() else {
        return Vec::new();
    };
    let mut pending = vec![root.clone()];
    let mut visited = HashSet::from([root.clone()]);
    let mut manifests = Vec::new();

    while let Some(dir) = pending.pop() {
        let manifest = dir.join("SKILL.md");
        if dir != root && manifest.is_file() {
            if let Ok(canonical) = manifest.canonicalize()
                && canonical.starts_with(&root)
            {
                manifests.push(canonical);
            }
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for path in entries.filter_map(|entry| entry.ok().map(|entry| entry.path())) {
            if !path.is_dir() {
                continue;
            }
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with('.'))
            {
                continue;
            }
            let Ok(canonical) = path.canonicalize() else {
                continue;
            };
            let canonical_is_hidden = canonical
                .strip_prefix(&root)
                .ok()
                .is_some_and(|relative| {
                    relative.components().any(|component| {
                        matches!(component, std::path::Component::Normal(name) if name.to_string_lossy().starts_with('.'))
                    })
                });
            if canonical.starts_with(&root)
                && !canonical_is_hidden
                && visited.insert(canonical.clone())
            {
                pending.push(canonical);
            }
        }
    }
    manifests.sort();
    manifests
}

/// Discover skills and apply Hermes conditional activation for the current
/// session. This is filtering only; surviving discovery order is unchanged.
pub fn discover_for_session(
    cwd: &Path,
    cfg: &SkillsConfig,
    activation: &ActivationContext,
) -> Result<Vec<Skill>> {
    Ok(discover(cwd, cfg)?
        .into_iter()
        .filter(|skill| skill_is_active(skill, activation))
        .collect())
}

/// Best-effort session inventory for UI/server surfaces that have the active
/// agent name but not the live [`crate::engine::tool::ToolBox`]. Agent
/// frontmatter is the authoritative pre-spawn tool grant; live tool calls use
/// the exact toolbox through [`discover_for_session`] instead.
pub fn discover_for_agent(cwd: &Path, cfg: &SkillsConfig, agent_name: &str) -> Result<Vec<Skill>> {
    let tool_names = crate::agents::resolve(cwd, agent_name)
        .ok()
        .flatten()
        .and_then(|agent| agent.tools)
        .unwrap_or_default();
    let activation = ActivationContext::from_tool_names(tool_names.iter().map(String::as_str));
    discover_for_session(cwd, cfg, &activation)
}

pub fn skill_is_active(skill: &Skill, activation: &ActivationContext) -> bool {
    let hermes = &skill.frontmatter.metadata.hermes;
    let platforms = if skill.frontmatter.platforms.is_empty() {
        &hermes.platforms
    } else {
        &skill.frontmatter.platforms
    };
    (platforms.is_empty() || platforms.iter().any(|p| p == &activation.platform))
        && hermes
            .requires_tools
            .iter()
            .all(|tool| activation.tools.contains(tool))
        && hermes
            .requires_toolsets
            .iter()
            .all(|toolset| activation.toolsets.contains(toolset))
        && !hermes
            .fallback_for_tools
            .iter()
            .any(|tool| activation.tools.contains(tool))
        && !hermes
            .fallback_for_toolsets
            .iter()
            .any(|toolset| activation.toolsets.contains(toolset))
}

/// Parse one `SKILL.md` into a [`Skill`] (frontmatter only — the body is
/// loaded on demand by [`load_body`]). Errors on missing/unparseable
/// frontmatter so [`discover`] can skip-and-warn.
fn parse_skill(path: &Path) -> Result<Skill> {
    let raw = read_markdown_capped(path)?;
    let (frontmatter_src, _body) = split_frontmatter(&raw)
        .with_context(|| format!("no YAML frontmatter in {}", path.display()))?;
    let frontmatter: SkillFrontmatter = serde_yaml::from_str(frontmatter_src)
        .with_context(|| format!("parsing frontmatter in {}", path.display()))?;
    if frontmatter.name.trim().is_empty() {
        anyhow::bail!("SKILL.md frontmatter `name` is empty");
    }
    // A skill that is neither model-invokable nor user-invocable can never
    // run — treat it as a config error (skip-and-warn via `discover`)
    // rather than carrying a silent no-op skill through the catalog.
    if frontmatter.disable_model_invocation && !frontmatter.user_invocable {
        anyhow::bail!(
            "SKILL.md frontmatter sets both `disable-model-invocation: true` and `user-invocable: false` — the skill would be invocable by neither the model nor the user"
        );
    }
    Ok(Skill {
        frontmatter,
        source: path.to_path_buf(),
    })
}

/// Load a skill's raw markdown body (everything after the frontmatter).
/// On-demand: called only when a skill is selected or invoked.
pub fn load_body(skill: &Skill) -> Result<String> {
    let raw = read_markdown_capped(&skill.source)?;
    match split_frontmatter(&raw) {
        Some((_, body)) => Ok(body.to_string()),
        // A skill with no frontmatter shouldn't have made it through
        // discovery, but tolerate it: the whole file is the body.
        None => Ok(raw),
    }
}

/// Load one progressive-disclosure support file from an Agent Skills package.
/// Only standard package directories are reachable; absolute paths, traversal,
/// symlink escapes, directories, and non-UTF-8 files are rejected.
pub fn load_support_file(skill: &Skill, relative: &Path) -> Result<String> {
    validate_support_relative(relative)?;

    let package = package_root(skill)
        .canonicalize()
        .context("canonicalizing skill package")?;
    let canonical = package
        .join(relative)
        .canonicalize()
        .with_context(|| format!("canonicalizing support file {}", relative.display()))?;
    if !canonical.starts_with(&package) || !canonical.is_file() {
        anyhow::bail!("support file escapes its skill package or is not a file");
    }
    read_markdown_capped(&canonical)
}

pub(crate) fn validate_support_relative(relative: &Path) -> Result<()> {
    use std::path::Component;

    if relative.as_os_str().is_empty() || relative.is_absolute() {
        anyhow::bail!("support file path must be a non-empty relative path");
    }
    let mut components = relative.components();
    let Some(Component::Normal(first)) = components.next() else {
        anyhow::bail!("support file path is invalid");
    };
    if !SUPPORT_DIRS.iter().any(|allowed| first == *allowed) {
        anyhow::bail!(
            "support file must be under one of: {}",
            SUPPORT_DIRS.join(", ")
        );
    }
    if components.any(|component| !matches!(component, Component::Normal(_))) {
        anyhow::bail!("support file path may not contain traversal components");
    }
    Ok(())
}

pub(crate) fn validate_managed_skill_contents(
    raw: &str,
    expected_name: &str,
) -> Result<SkillFrontmatter> {
    if raw.chars().count() > MAX_MANAGED_SKILL_CHARS {
        anyhow::bail!("SKILL.md exceeds {MAX_MANAGED_SKILL_CHARS} character limit");
    }
    let (frontmatter_src, body) =
        split_frontmatter(raw).context("SKILL.md needs YAML frontmatter")?;
    let frontmatter: SkillFrontmatter =
        serde_yaml::from_str(frontmatter_src).context("parsing SKILL.md frontmatter")?;
    if frontmatter.name != expected_name {
        anyhow::bail!(
            "SKILL.md frontmatter name `{}` must remain `{expected_name}`",
            frontmatter.name
        );
    }
    if !managed_skill_name_valid(&frontmatter.name) {
        anyhow::bail!(
            "skill name must match ^[a-z0-9][a-z0-9._-]*$ and contain at most 64 characters"
        );
    }
    let description = frontmatter.description.trim();
    if description.is_empty() || description.chars().count() > 1024 {
        anyhow::bail!("skill description must contain 1..=1024 characters");
    }
    if body.trim().is_empty() {
        anyhow::bail!("SKILL.md body must not be empty");
    }
    if frontmatter.disable_model_invocation && !frontmatter.user_invocable {
        anyhow::bail!("skill must be invocable by the model or the user");
    }
    Ok(frontmatter)
}

pub(crate) fn managed_skill_name_valid(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.chars().count() <= 64
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && chars.all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-')
        })
}

/// Validate the subset Cockpit's future skill writer must emit. Discovery is
/// deliberately more permissive for third-party read compatibility.
#[cfg_attr(not(test), allow(dead_code))]
pub fn validate_conformant_package(skill: &Skill) -> Result<()> {
    let name = skill.frontmatter.name.as_str();
    let name_valid = (1..=64).contains(&name.len())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && !name.contains("--")
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !name_valid {
        anyhow::bail!("skill name is not Agent Skills-conformant");
    }
    let parent_name = skill
        .source
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str());
    if parent_name != Some(name) {
        anyhow::bail!("skill name must match its package directory");
    }
    let description = skill.frontmatter.description.trim();
    if description.is_empty() || description.chars().count() > 1024 {
        anyhow::bail!("skill description must contain 1..=1024 characters");
    }
    Ok(())
}

fn read_markdown_capped(path: &Path) -> Result<String> {
    let bytes = match cockpit_host::bounded::read_at_most(path, MAX_MARKDOWN_BYTES) {
        Ok(bytes) => bytes,
        Err(cockpit_host::bounded::BoundedIoError::Limit { actual, .. }) => {
            tracing::warn!(
                path = %path.display(),
                size = actual,
                limit = MAX_MARKDOWN_BYTES,
                "skipping oversized SKILL.md"
            );
            anyhow::bail!(
                "SKILL.md exceeds {} byte limit: {}",
                MAX_MARKDOWN_BYTES,
                path.display()
            );
        }
        Err(error) => {
            return Err(error).context(format!("reading {}", path.display()));
        }
    };
    String::from_utf8(bytes).with_context(|| format!("reading {}", path.display()))
}

/// Split a `---`-delimited YAML frontmatter block off the front of a
/// markdown document. Returns `(frontmatter_src, body)`. The opening
/// `---` must be the first line; the closing `---` ends the block. `None`
/// when there's no well-formed frontmatter.
///
/// This is cockpit's shared frontmatter splitter for SKILL.md (and the
/// agent-file format); it deliberately avoids pulling in a separate
/// front-matter crate — the parse itself is `serde_yaml`, already a
/// dependency.
fn split_frontmatter(raw: &str) -> Option<(&str, &str)> {
    // Tolerate a leading BOM before the fence.
    let rest = raw.trim_start_matches('\u{feff}');
    // The opening fence must be the first content.
    if !rest.starts_with("---") {
        return None;
    }
    // Advance past the opening `---` line.
    let after_open = {
        let nl = rest.find('\n')?;
        // Ensure the opening line is *only* `---` (allow trailing CR).
        let first_line = rest[..nl].trim_end_matches('\r');
        if first_line != "---" {
            return None;
        }
        &rest[nl + 1..]
    };

    // Find the closing fence: a line consisting solely of `---`.
    let mut idx = 0usize;
    for line in after_open.split_inclusive('\n') {
        let bare = line.trim_end_matches('\n').trim_end_matches('\r');
        if bare == "---" {
            let fm = &after_open[..idx];
            let body_start = idx + line.len();
            let body = after_open.get(body_start..).unwrap_or("");
            // Trim a single leading newline so the body starts cleanly.
            let body = body.strip_prefix('\n').unwrap_or(body);
            return Some((fm, body));
        }
        idx += line.len();
    }
    None
}

/// Resolve the ordered list of scan directories for `cwd`. The configured
/// `scan_dirs` are authoritative: an empty list yields **zero** directories
/// (no implicit fallback). With `cfg.ancestor_walk` on, each *relative*
/// entry expands to cwd plus every ancestor up to the git worktree root.
/// Returned paths are absolute and may not exist — [`discover`] tolerates
/// missing dirs.
pub fn resolve_scan_dirs(cwd: &Path, cfg: &SkillsConfig) -> Vec<PathBuf> {
    resolve_configured_scan_dirs(cwd, cfg)
        .into_iter()
        .filter(|dir| skill_scan_dir_allowed_by_trust(dir))
        .collect()
}

fn resolve_configured_scan_dirs(cwd: &Path, cfg: &SkillsConfig) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in &cfg.scan_dirs {
        resolve_dir_entry(entry, cwd, cfg.ancestor_walk, &mut out);
    }
    for entry in &cfg.external_dirs {
        resolve_dir_entry(entry, cwd, false, &mut out);
    }
    out
}

fn skill_scan_dir_allowed_by_trust(dir: &Path) -> bool {
    !crate::config::trust::path_blocked_by_workspace_trust(dir) || is_user_global_skill_dir(dir)
}

fn is_user_global_skill_dir(dir: &Path) -> bool {
    let Some(home) = dirs::home_dir() else {
        return false;
    };
    let dir = lexical_absolute(dir);
    user_global_skill_roots(&home)
        .into_iter()
        .any(|root| dir == root || dir.starts_with(root))
}

fn user_global_skill_roots(home: &Path) -> [PathBuf; 4] {
    [
        home.join(".agents").join("skills"),
        home.join(".claude").join("skills"),
        home.join(".cockpit").join("skills"),
        home.join(".hermes").join("skills"),
    ]
}

fn lexical_absolute(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    lexical_normalize(&abs)
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve a single configured scan-dir entry, pushing the resulting
/// path(s) onto `out`. Supports `~` home expansion, `$VAR` references (via
/// [`crate::envref`]), and relative paths resolved against `cwd`. A blank
/// or home-unexpandable `~` entry pushes nothing.
///
/// When `ancestor_walk` is set and the entry resolves to a *relative*
/// path, it expands to that path under `cwd` and under every ancestor up
/// to (and including) the git worktree root — so a repo-root skills dir is
/// found from any subdirectory. Absolute / `~` / `$VAR`-rooted entries are
/// unaffected by the toggle.
fn resolve_dir_entry(entry: &str, cwd: &Path, ancestor_walk: bool, out: &mut Vec<PathBuf>) {
    // `$VAR` expansion first, so a value like `$PROJECTS/skills` becomes
    // a concrete path before tilde / relative handling.
    let expanded = crate::envref::resolve(entry).value;
    let expanded = expanded.trim();
    if expanded.is_empty() {
        return;
    }

    // `~` / `~/...` home expansion.
    let tilde = shellexpand::tilde(expanded).into_owned();
    let rel = PathBuf::from(tilde);

    if rel.is_absolute() {
        out.push(rel);
        return;
    }

    if !ancestor_walk {
        out.push(cwd.join(&rel));
        return;
    }

    // Ancestor walk: join the relative tail under cwd and each ancestor up
    // to (and including) the git worktree root.
    let stop_at = crate::git::find_worktree_root(cwd);
    let mut dir: Option<&Path> = Some(cwd);
    while let Some(d) = dir {
        out.push(d.join(&rel));
        if let Some(root) = &stop_at
            && d == root.as_path()
        {
            break;
        }
        dir = d.parent();
    }
}

/// Render a skill body for injection into context, applying the
/// auto-`!`-command toggle. `redact` scrubs Claude-mode command output
/// before it enters context (GOALS §7) — table-known literals and novel
/// secret-shaped values the command itself surfaces. In Codex mode
/// (`auto_bang_commands == false`) directives are returned verbatim and
/// no command runs.
pub fn render_body(
    body: &str,
    cwd: &Path,
    auto_bang_commands: bool,
    local_knowledge_write_fence_active: bool,
    redact: &RedactionTable,
) -> String {
    if !auto_bang_commands
        || local_knowledge_write_fence_active
        || crate::config::trust::path_blocked_by_workspace_trust(cwd)
    {
        // Codex mode: inject verbatim.
        return body.to_string();
    }
    substitute_bang_commands(body, cwd, redact)
}

/// Walk `body` replacing each `` !`command` `` directive with the
/// command's stdout (Claude mode). Output passes through `redact` before
/// it lands in the returned string. Failures inject a bracketed error
/// marker in place of the directive.
fn substitute_bang_commands(body: &str, cwd: &Path, redact: &RedactionTable) -> String {
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    // `i` always sits on a char boundary: the opener `` !` `` and the
    // closing backtick are single-byte ASCII, and the copy step below
    // advances by whole `str::find`/slice spans that begin and end on
    // boundaries.
    let mut i = 0;
    while i < bytes.len() {
        // Look for the `` !` `` opener at the current boundary.
        if bytes[i] == b'!'
            && i + 1 < bytes.len()
            && bytes[i + 1] == b'`'
            && let Some(close_rel) = body[i + 2..].find('`')
        {
            let cmd = &body[i + 2..i + 2 + close_rel];
            let replacement = run_bang_command(cmd, cwd, redact);
            out.push_str(&replacement);
            i = i + 2 + close_rel + 1;
            continue;
        }
        // Copy up to (but not including) the next `!`, or the rest of the
        // string if there's no further `!`. This advances by a whole
        // char-boundary-aligned slice without per-codepoint bookkeeping.
        let next = body[i + 1..].find('!').map(|rel| i + 1 + rel);
        let end = next.unwrap_or(bytes.len());
        out.push_str(&body[i..end]);
        i = end;
    }
    out
}

/// Run one inline `!`-command and return the redacted stdout, or a
/// bracketed error marker on failure / nonzero exit. Never panics.
///
/// Every captured channel — stdout, stderr, and the echoed command inside
/// an error marker — runs through [`scrub_bang_output`] (the non-bypassable
/// GOALS §7 substitution-site scrub) before it can enter context, the
/// provider request, or any export.
fn run_bang_command(cmd: &str, cwd: &Path, redact: &RedactionTable) -> String {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return "[skill command error: empty command]".to_string();
    }
    let output = bang_command_invocation(trimmed).current_dir(cwd).output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Trim the trailing newline command stdout usually carries so
            // the substitution reads inline-naturally; scrub before the
            // output enters context.
            scrub_bang_output(redact, stdout.trim_end_matches('\n'))
        }
        Ok(out) => {
            let code = out
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signaled".to_string());
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stderr = scrub_bang_output(redact, stderr.trim());
            if stderr.is_empty() {
                redact.scrub(&format!(
                    "[skill command `{}` failed: exit {code}]",
                    scrub_bang_output(redact, trimmed)
                ))
            } else {
                redact.scrub(&format!(
                    "[skill command `{}` failed: exit {code}: {stderr}]",
                    scrub_bang_output(redact, trimmed)
                ))
            }
        }
        Err(e) => redact.scrub(&format!(
            "[skill command `{}` failed to run: {e}]",
            scrub_bang_output(redact, trimmed)
        )),
    }
}

/// The substitution-site scrub for captured `!`-command text: table-known
/// literals first via [`RedactionTable::scrub`], then novel secret-shaped
/// values the table has no entry for
/// ([`RedactionTable::scrub_novel_command_output_secrets`] — secrets first
/// surfaced by the command itself, which dispatch-time table scrubbing can
/// never catch). Both run before the text can enter context.
fn scrub_bang_output(redact: &RedactionTable, text: &str) -> String {
    redact.scrub_novel_command_output_secrets(&redact.scrub(text))
}

/// The fixed `!`-command shell invocation (owner-adopted design, Windows
/// launch decision): the platform's executable shell with no profile, no
/// interactive state, and explicit UTF-8.  The skill command text is passed
/// as the whole script argument — there is no implicit command-shell string
/// interpolation beyond the documented skill syntax, and the shell choice
/// is deliberately not a config knob.
#[cfg(not(windows))]
fn bang_command_invocation(command: &str) -> Command {
    let mut invocation = Command::new("sh");
    invocation.arg("-c").arg(command);
    invocation
}

#[cfg(windows)]
fn bang_command_invocation(command: &str) -> Command {
    let mut invocation = Command::new("powershell");
    invocation
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(windows_bang_script(command));
    invocation
}

/// One PowerShell script: an explicit UTF-8 preamble (console and pipeline
/// encodings), the verbatim skill command, and `exit $LASTEXITCODE` so a
/// failing native command reports its exit status the way `sh -c` does.
#[cfg(windows)]
fn windows_bang_script(command: &str) -> String {
    format!(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); \
         $OutputEncoding = [System.Text.UTF8Encoding]::new(); \
         {command}; exit $LASTEXITCODE"
    )
}

/// Locate a discovered skill by exact `name`. Used by the `skill` tool's
/// manual-invocation path.
pub fn find_by_name<'a>(skills: &'a [Skill], name: &str) -> Option<&'a Skill> {
    skills.iter().find(|s| s.frontmatter.name == name)
}

pub fn is_model_invocable(skill: &Skill) -> bool {
    !skill.frontmatter.disable_model_invocation
}

pub fn find_model_invocable_by_name<'a>(skills: &'a [Skill], name: &str) -> Option<&'a Skill> {
    skills
        .iter()
        .find(|skill| skill.frontmatter.name == name && is_model_invocable(skill))
}

/// Build the model-facing catalog string: one `- name: description` line per
/// skill. This is the only payload the utility selector and live agent catalog
/// ever see before a body is explicitly loaded (token economy, GOALS §10).
pub fn catalog_lines<'a>(skills: impl IntoIterator<Item = &'a Skill>) -> String {
    let mut out = String::new();
    for s in skills {
        out.push_str("- ");
        out.push_str(&s.frontmatter.name);
        out.push_str(": ");
        out.push_str(&catalog_description(&s.frontmatter.description));
        out.push('\n');
    }
    out
}

fn catalog_description(description: &str) -> String {
    let description = description.split_whitespace().collect::<Vec<_>>().join(" ");
    if description.chars().count() <= MAX_CATALOG_DESCRIPTION_CHARS {
        return description;
    }
    let keep = MAX_CATALOG_DESCRIPTION_CHARS.saturating_sub(1);
    let mut truncated: String = description.chars().take(keep).collect();
    if let Some(space) = truncated.rfind(' ') {
        truncated.truncate(space);
    }
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::extended::RedactConfig;

    fn trusted_policy(root: &Path) -> crate::config::trust::WorkspaceTrustPolicy {
        crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::TrustRoot {
                opened_path: root.to_path_buf(),
                root: root.to_path_buf(),
                kind: crate::config::trust::TrustRootKind::Directory,
            },
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        }
    }

    fn trusted_discover(root: &Path, cfg: &SkillsConfig) -> Result<Vec<Skill>> {
        crate::config::trust::with_workspace_trust_policy(trusted_policy(root), || {
            discover(root, cfg)
        })
    }

    fn trusted_resolve_scan_dirs(root: &Path, cfg: &SkillsConfig) -> Vec<PathBuf> {
        crate::config::trust::with_workspace_trust_policy(trusted_policy(root), || {
            resolve_scan_dirs(root, cfg)
        })
    }

    fn trusted_render_body(
        body: &str,
        root: &Path,
        expand_commands: bool,
        redact: &RedactionTable,
    ) -> String {
        crate::config::trust::with_workspace_trust_policy(trusted_policy(root), || {
            render_body(body, root, expand_commands, false, redact)
        })
    }

    fn trusted_package_target_for_path(
        path: &Path,
        root: &Path,
        cfg: &SkillsConfig,
    ) -> Option<SkillPackageTarget> {
        crate::config::trust::with_workspace_trust_policy(trusted_policy(root), || {
            package_target_for_path(path, root, cfg)
        })
    }

    fn trusted_invalidate_catalog_cache(root: &Path, cfg: &SkillsConfig) {
        crate::config::trust::with_workspace_trust_policy(trusted_policy(root), || {
            invalidate_catalog_cache(root, cfg);
        });
    }

    fn no_redact() -> RedactionTable {
        RedactionTable::build(&RedactConfig::default(), Path::new("/")).unwrap()
    }

    fn write_skill(dir: &Path, name: &str, frontmatter: &str, body: &str) {
        let sub = dir.join(name);
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("SKILL.md"), format!("{frontmatter}{body}")).unwrap();
    }

    fn write_large_skill(dir: &Path, name: &str, size: u64) {
        let sub = dir.join(name);
        std::fs::create_dir_all(&sub).unwrap();
        let path = sub.join("SKILL.md");
        std::fs::write(&path, "---\nname: large\ndescription: too large\n---\n").unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .set_len(size)
            .unwrap();
    }

    #[test]
    fn split_frontmatter_basic() {
        let raw = "---\nname: x\ndescription: y\n---\nBODY HERE\n";
        let (fm, body) = split_frontmatter(raw).unwrap();
        assert!(fm.contains("name: x"));
        assert_eq!(body, "BODY HERE\n");
    }

    #[test]
    fn split_frontmatter_none_when_no_fence() {
        assert!(split_frontmatter("no frontmatter here").is_none());
    }

    #[test]
    fn split_frontmatter_none_when_unterminated() {
        assert!(split_frontmatter("---\nname: x\nno close").is_none());
    }

    #[test]
    fn parse_skill_reads_frontmatter() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "greet",
            "---\nname: greet\ndescription: say hi\n---\n",
            "BODY",
        );
        let skill = parse_skill(&tmp.path().join("greet").join("SKILL.md")).unwrap();
        assert_eq!(skill.frontmatter.name, "greet");
        assert_eq!(skill.frontmatter.description, "say hi");
        assert!(skill.frontmatter.model.is_none());
    }

    #[test]
    fn parse_skill_preserves_optional_model() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "m",
            "---\nname: m\ndescription: d\nmodel: anthropic:claude\n---\n",
            "B",
        );
        let skill = parse_skill(&tmp.path().join("m").join("SKILL.md")).unwrap();
        assert_eq!(skill.frontmatter.model.as_deref(), Some("anthropic:claude"));
    }

    #[test]
    fn parse_skill_invocation_flags_default_permissive() {
        // A 3-field skill (name/description/model only) defaults to both
        // user-invocable and model-invokable — unchanged from before.
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "plain",
            "---\nname: plain\ndescription: d\n---\n",
            "B",
        );
        let skill = parse_skill(&tmp.path().join("plain").join("SKILL.md")).unwrap();
        assert!(!skill.frontmatter.disable_model_invocation);
        assert!(skill.frontmatter.user_invocable);
        assert!(skill.frontmatter.extra.is_empty());
    }

    #[test]
    fn parse_skill_reads_invocation_flags() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "useronly",
            "---\nname: useronly\ndescription: d\ndisable-model-invocation: true\n---\n",
            "B",
        );
        let skill = parse_skill(&tmp.path().join("useronly").join("SKILL.md")).unwrap();
        assert!(skill.frontmatter.disable_model_invocation);
        assert!(skill.frontmatter.user_invocable);

        write_skill(
            tmp.path(),
            "modelonly",
            "---\nname: modelonly\ndescription: d\nuser-invocable: false\n---\n",
            "B",
        );
        let skill = parse_skill(&tmp.path().join("modelonly").join("SKILL.md")).unwrap();
        assert!(!skill.frontmatter.disable_model_invocation);
        assert!(!skill.frontmatter.user_invocable);
    }

    #[test]
    fn parse_skill_accepts_unknown_claude_fields() {
        // Forward-compat: extra Claude frontmatter fields parse cleanly into
        // the flattened catch-all instead of erroring.
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "rich",
            "---\nname: rich\ndescription: d\nwhen_to_use: when stuck\npaths:\n  - src/**\nallowed-tools:\n  - read\neffort: high\n---\n",
            "B",
        );
        let skill = parse_skill(&tmp.path().join("rich").join("SKILL.md")).unwrap();
        assert_eq!(skill.frontmatter.name, "rich");
        // The unknown fields land in `extra`, not an error.
        assert!(skill.frontmatter.extra.contains_key("when_to_use"));
        assert!(skill.frontmatter.extra.contains_key("paths"));
        assert!(skill.frontmatter.extra.contains_key("allowed-tools"));
        assert!(skill.frontmatter.extra.contains_key("effort"));
    }

    #[test]
    fn parse_skill_rejects_neither_invocable() {
        // Both flags set to their non-permissive value → invocable by
        // neither model nor user → config error (so `discover` skip-and-warns).
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "dead",
            "---\nname: dead\ndescription: d\ndisable-model-invocation: true\nuser-invocable: false\n---\n",
            "B",
        );
        let err = parse_skill(&tmp.path().join("dead").join("SKILL.md")).unwrap_err();
        assert!(
            err.to_string().contains("disable-model-invocation")
                && err.to_string().contains("user-invocable"),
            "got {err}"
        );
    }

    #[test]
    fn discover_skips_neither_invocable_config_error() {
        // The both-false skill is warned-and-skipped at discovery, not
        // carried through as a silent no-op; its sibling survives.
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(&scan, "ok", "---\nname: ok\ndescription: d\n---\n", "B");
        write_skill(
            &scan,
            "dead",
            "---\nname: dead\ndescription: d\ndisable-model-invocation: true\nuser-invocable: false\n---\n",
            "B",
        );
        let cfg = SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        };
        let found = trusted_discover(tmp.path(), &cfg).unwrap();
        let names: Vec<&str> = found.iter().map(|s| s.frontmatter.name.as_str()).collect();
        assert_eq!(names, vec!["ok"], "the both-false skill must be skipped");
    }

    #[test]
    fn discover_finds_configured_dir_and_skips_malformed() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(&scan, "ok", "---\nname: ok\ndescription: d\n---\n", "B");
        // Malformed: no frontmatter at all.
        let bad = scan.join("bad");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("SKILL.md"), "just text, no frontmatter").unwrap();
        // Malformed: frontmatter missing required field.
        write_skill(&scan, "nodesc", "---\nname: nodesc\n---\n", "B");

        let cfg = SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        };
        let found = trusted_discover(tmp.path(), &cfg).unwrap();
        let names: Vec<&str> = found.iter().map(|s| s.frontmatter.name.as_str()).collect();
        assert_eq!(names, vec!["ok"], "only the well-formed skill survives");
    }

    #[test]
    fn malformed_skill_manifest_is_skipped_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(
            &scan,
            "good",
            "---\nname: good\ndescription: survives\n---\n",
            "B",
        );
        write_skill(&scan, "bad", "---\nname: bad\n---\n", "B");
        let cfg = SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        };

        let found = trusted_discover(tmp.path(), &cfg).unwrap();

        assert_eq!(
            found
                .iter()
                .map(|s| s.frontmatter.name.as_str())
                .collect::<Vec<_>>(),
            vec!["good"]
        );
    }

    #[test]
    fn skill_discovery_cache_hit_performs_no_walk() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(&scan, "one", "---\nname: one\ndescription: d\n---\n", "B");
        let cfg = SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        };
        let first = trusted_discover(tmp.path(), &cfg).unwrap();
        std::fs::remove_dir_all(&scan).unwrap();
        let second = trusted_discover(tmp.path(), &cfg).unwrap();

        assert_eq!(
            first
                .iter()
                .map(|s| s.frontmatter.name.as_str())
                .collect::<Vec<_>>(),
            vec!["one"]
        );
        assert_eq!(
            second
                .iter()
                .map(|s| s.frontmatter.name.as_str())
                .collect::<Vec<_>>(),
            vec!["one"],
            "cache hit must return cached skills without reading the removed scan dir"
        );
    }

    #[test]
    fn skill_discovery_walks_after_invalidation() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(&scan, "one", "---\nname: one\ndescription: d\n---\n", "B");
        let cfg = SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        };
        trusted_invalidate_catalog_cache(tmp.path(), &cfg);
        trusted_discover(tmp.path(), &cfg).unwrap();
        write_skill(&scan, "two", "---\nname: two\ndescription: d\n---\n", "B");
        reset_discovery_walk_call_count();

        trusted_invalidate_catalog_cache(tmp.path(), &cfg);
        let found = trusted_discover(tmp.path(), &cfg).unwrap();

        assert!(
            discovery_walk_call_count() > 0,
            "explicit invalidation makes the next discovery walk"
        );
        assert_eq!(
            found
                .iter()
                .map(|s| s.frontmatter.name.as_str())
                .collect::<Vec<_>>(),
            vec!["one", "two"]
        );
    }

    #[test]
    fn discover_skips_oversized_skill_markdown() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(
            &scan,
            "small",
            "---\nname: small\ndescription: d\n---\n",
            "B",
        );
        write_large_skill(&scan, "large", MAX_MARKDOWN_BYTES + 1);

        let cfg = SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        };
        let found = trusted_discover(tmp.path(), &cfg).unwrap();
        let names: Vec<&str> = found.iter().map(|s| s.frontmatter.name.as_str()).collect();
        assert_eq!(names, vec!["small"]);
    }

    #[test]
    fn load_body_rejects_oversized_skill_markdown() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        write_large_skill(&scan, "large", MAX_MARKDOWN_BYTES + 1);
        let skill = Skill {
            frontmatter: SkillFrontmatter {
                name: "large".to_string(),
                description: "d".to_string(),
                ..Default::default()
            },
            source: scan.join("large").join("SKILL.md"),
        };

        let err = load_body(&skill).unwrap_err();

        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn discover_keeps_small_skill_markdown() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        let body = "x".repeat(100 * 1024);
        write_skill(
            &scan,
            "small",
            "---\nname: small\ndescription: d\n---\n",
            &body,
        );

        let cfg = SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        };
        let found = trusted_discover(tmp.path(), &cfg).unwrap();

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].frontmatter.name, "small");
    }

    #[test]
    fn ignore_config_excludes_repo_local_skills() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join(".agents").join("skills");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(&scan, "evil", "---\nname: evil\ndescription: d\n---\n", "B");
        let cfg = SkillsConfig {
            scan_dirs: vec![".agents/skills".to_string()],
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        };
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        };

        let found = crate::config::trust::with_workspace_trust_policy(policy, || {
            discover(tmp.path(), &cfg)
        })
        .unwrap();

        assert!(found.is_empty(), "repo-local skill must be invisible");
    }

    #[test]
    fn ignored_workspace_skill_is_not_treated_as_a_managed_write_target() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join(".agents").join("skills");
        write_skill(
            &scan,
            "local",
            "---\nname: local\ndescription: d\n---\n",
            "B",
        );
        let cfg = skills_cfg(vec![".agents/skills"], false);
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        };

        let target = crate::config::trust::with_workspace_trust_policy(policy, || {
            package_target_for_path(&scan.join("local/SKILL.md"), tmp.path(), &cfg)
        });

        assert!(
            target.is_none(),
            "untrusted skill directories remain plain paths"
        );
    }

    #[test]
    fn trust_mode_keeps_repo_local_skills() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join(".agents").join("skills");
        std::fs::create_dir_all(&scan).unwrap();
        write_skill(&scan, "ok", "---\nname: ok\ndescription: d\n---\n", "B");
        let cfg = SkillsConfig {
            scan_dirs: vec![".agents/skills".to_string()],
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk: false,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        };
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };

        let found = crate::config::trust::with_workspace_trust_policy(policy, || {
            discover(tmp.path(), &cfg)
        })
        .unwrap();

        let names: Vec<&str> = found.iter().map(|s| s.frontmatter.name.as_str()).collect();
        assert_eq!(names, vec!["ok"]);
    }

    fn skills_cfg(scan_dirs: Vec<&str>, ancestor_walk: bool) -> SkillsConfig {
        SkillsConfig {
            scan_dirs: scan_dirs.into_iter().map(str::to_string).collect(),
            external_dirs: Vec::new(),
            auto_bang_commands: false,
            ancestor_walk,
            write_approval: false,
            prune_builtins: false,
            consolidate: false,
        }
    }

    #[test]
    fn resolve_scan_dirs_expands_env_and_relative() {
        let cwd = Path::new("/tmp/project");
        // Relative resolves against cwd; absolute stays absolute.
        let cfg = skills_cfg(vec!["skills/dir", "/abs/skills"], false);
        let dirs = trusted_resolve_scan_dirs(cwd, &cfg);
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/tmp/project/skills/dir"),
                PathBuf::from("/abs/skills"),
            ]
        );
    }

    #[test]
    fn resolve_scan_dirs_expands_dollar_var() {
        let env = crate::test_env::lock();
        env.set_var("COCKPIT_TEST_SKILLS_ROOT", "/var/skills");
        let cfg = skills_cfg(vec!["$COCKPIT_TEST_SKILLS_ROOT/sub"], false);
        let dirs = trusted_resolve_scan_dirs(Path::new("/cwd"), &cfg);
        assert_eq!(dirs, vec![PathBuf::from("/var/skills/sub")]);
    }

    #[test]
    fn resolve_scan_dirs_empty_yields_no_dirs() {
        // No implicit fallback: an empty list scans nothing.
        let cfg = skills_cfg(vec![], false);
        assert!(trusted_resolve_scan_dirs(Path::new("/tmp/project"), &cfg).is_empty());
    }

    #[test]
    fn resolve_scan_dirs_relative_respects_ancestor_walk_toggle() {
        // A real git worktree so `find_worktree_root` returns a stop point.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let git_init = std::process::Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&root)
            .status();
        // Skip on hosts without git rather than fail spuriously.
        if !matches!(git_init, Ok(s) if s.success()) {
            return;
        }
        // Confirm git agrees on the worktree root (some CI sandboxes refuse
        // to treat a tmp dir as a repo); bail cleanly if it doesn't.
        if crate::git::find_worktree_root(&root).as_deref() != Some(root.as_path()) {
            return;
        }
        let nested = root.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();

        // Ancestor walk OFF: the relative entry resolves against cwd only.
        let off = skills_cfg(vec![".agents/skills"], false);
        let dirs_off = trusted_resolve_scan_dirs(&nested, &off);
        assert_eq!(dirs_off, vec![nested.join(".agents").join("skills")]);

        // Ancestor walk ON: cwd plus every ancestor up to and including
        // the worktree root.
        let on = skills_cfg(vec![".agents/skills"], true);
        let dirs_on = trusted_resolve_scan_dirs(&nested, &on);
        let expected = vec![
            nested.join(".agents").join("skills"),
            root.join("a").join(".agents").join("skills"),
            root.join(".agents").join("skills"),
        ];
        assert_eq!(dirs_on, expected);
    }

    #[test]
    fn resolve_scan_dirs_absolute_entry_ignores_ancestor_walk() {
        let cfg = skills_cfg(vec!["/abs/skills"], true);
        let dirs = trusted_resolve_scan_dirs(Path::new("/tmp/a/b"), &cfg);
        assert_eq!(dirs, vec![PathBuf::from("/abs/skills")]);
    }

    #[test]
    fn render_body_codex_mode_injects_verbatim() {
        let body = "before !`echo hi` after";
        let out = render_body(body, Path::new("."), false, false, &no_redact());
        assert_eq!(out, body, "Codex mode leaves the directive verbatim");
    }

    #[test]
    fn render_body_claude_mode_runs_command() {
        let body = "value: !`echo hello`";
        let out = trusted_render_body(body, Path::new("."), true, &no_redact());
        assert_eq!(out, "value: hello", "Claude mode substitutes stdout");
    }

    #[test]
    fn render_body_forces_bang_off_under_ignore_config_root() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        };
        let body = "value: !`echo should-not-run`";

        let out = crate::config::trust::with_workspace_trust_policy(policy, || {
            render_body(body, tmp.path(), true, false, &no_redact())
        });

        assert_eq!(out, body);
    }

    #[test]
    #[cfg(not(windows))]
    fn bang_command_invocation_uses_sh_on_unix_like_platforms() {
        let invocation = bang_command_invocation("echo hi");
        assert_eq!(invocation.get_program(), "sh");
        let args: Vec<_> = invocation.get_args().collect();
        assert_eq!(args, ["-c", "echo hi"]);
    }

    #[test]
    #[cfg(windows)]
    fn bang_command_invocation_uses_powershell_with_no_profile_and_explicit_utf8() {
        let invocation = bang_command_invocation("Write-Output ok");
        assert_eq!(invocation.get_program(), "powershell");
        let args: Vec<_> = invocation.get_args().collect();
        assert_eq!(args[0], "-NoProfile");
        assert!(args.contains(&"-NonInteractive"));
        assert!(args.contains(&"-Command"));
        let script = args
            .last()
            .expect("the script is the final argument")
            .to_string_lossy()
            .into_owned();
        assert!(script.contains("UTF8Encoding"), "{script:?}");
        assert!(script.contains("exit $LASTEXITCODE"), "{script:?}");
        assert!(script.contains("Write-Output ok"), "{script:?}");
        // The command is the whole script, not interpolated into an
        // implicit command shell.
        assert!(!args.iter().any(|arg| *arg == "cmd"), "{script:?}");
    }

    #[test]
    fn render_body_claude_mode_error_marker_on_failure() {
        let body = "x !`exit 3` y";
        let out = trusted_render_body(body, Path::new("."), true, &no_redact());
        assert!(
            out.contains("[skill command") && out.contains("exit 3"),
            "expected an inline error marker, got {out:?}"
        );
        // The turn never crashes — surrounding text survives.
        assert!(out.starts_with("x ") && out.ends_with(" y"));
    }

    #[test]
    fn render_body_claude_mode_scrubs_command_output_at_substitution_site() {
        // Table-known secrets are redacted where the directive is replaced
        // — the documented non-bypassable GOALS §7 scrub — not deferred to
        // dispatch time (issue #279 regression).
        let cfg = RedactConfig {
            denylist: vec!["SUPERSECRETTOKEN".to_string()],
            scan_ssh_keys: false,
            ..Default::default()
        };
        let redact = RedactionTable::build(&cfg, Path::new("/")).unwrap();
        let body = "leak: !`echo SUPERSECRETTOKEN`";
        let out = render_body(body, Path::new("."), true, false, &redact);
        assert!(!out.contains("SUPERSECRETTOKEN"), "got {out:?}");
        assert!(out.contains("REDACTED"), "got {out:?}");
    }

    #[test]
    fn render_body_claude_mode_redacts_novel_command_secrets_absent_from_table() {
        // The dispatch-time scrub only replaces values already registered
        // in the session table, so a secret first surfaced BY the command
        // itself (`!`cat .env``) must be redacted at the substitution site
        // (issue #279 regression).
        let body = "cfg !`echo \"API_TOKEN=novel-skill-secret-9f1a2b\"`";
        let out = trusted_render_body(body, Path::new("."), true, &no_redact());
        assert!(!out.contains("novel-skill-secret-9f1a2b"), "got {out:?}");
        assert!(
            out.contains("API_TOKEN=") && out.contains("REDACTED"),
            "key is preserved and the value redacted, got {out:?}"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn render_body_claude_mode_redacts_novel_secret_read_from_file() {
        // The issue's headline repro: a `!`-command that reads a secret the
        // table does not know yet (the secret lives in a file, so the
        // command text itself carries none).
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("leak.env"),
            "AWS_SESSION_TOKEN=freshly-minted-novel-token-8842\n",
        )
        .unwrap();
        let body = "env dump: !`cat leak.env`";
        let out = trusted_render_body(body, tmp.path(), true, &no_redact());
        assert!(
            !out.contains("freshly-minted-novel-token-8842"),
            "got {out:?}"
        );
        assert!(
            out.contains("AWS_SESSION_TOKEN=") && out.contains("REDACTED"),
            "got {out:?}"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn render_body_claude_mode_scrubs_table_known_secret_in_error_marker() {
        let cfg = RedactConfig {
            denylist: vec!["TABLESTDERRSECRET7".to_string()],
            scan_ssh_keys: false,
            ..Default::default()
        };
        let redact = RedactionTable::build(&cfg, Path::new("/")).unwrap();
        let body = "x !`echo TABLESTDERRSECRET7 >&2; exit 1` y";
        let out = render_body(body, Path::new("."), true, false, &redact);
        assert!(!out.contains("TABLESTDERRSECRET7"), "got {out:?}");
        assert!(out.contains("[skill command"), "got {out:?}");
    }

    #[test]
    #[cfg(not(windows))]
    fn render_body_claude_mode_redacts_novel_secret_in_error_marker_stderr() {
        // Stderr embedded in the failure marker is scrubbed for novel
        // secret-shaped values too, not just table-known literals. The
        // secret lives in a file so the command text itself carries none.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("err.env"),
            "DB_PASSWORD=novel-stderr-secret-77aa\n",
        )
        .unwrap();
        let body = "x !`cat err.env >&2; exit 1` y";
        let out = trusted_render_body(body, tmp.path(), true, &no_redact());
        assert!(!out.contains("novel-stderr-secret-77aa"), "got {out:?}");
        assert!(out.contains("[skill command"), "got {out:?}");
        assert!(out.contains("DB_PASSWORD="), "got {out:?}");
    }

    // Windows twins of the `!`-command scrub proofs above, exercised through
    // the PowerShell invocation: the C5 substitution-site scrub must cover
    // the Windows path identically (issue #283).
    #[test]
    #[cfg(windows)]
    fn windows_render_body_claude_mode_redacts_novel_secret_read_from_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("leak.env"),
            "AWS_SESSION_TOKEN=freshly-minted-novel-token-8842\n",
        )
        .unwrap();
        // `cat` is the PowerShell alias for Get-Content.
        let body = "env dump: !`cat leak.env`";
        let out = trusted_render_body(body, tmp.path(), true, &no_redact());
        assert!(
            !out.contains("freshly-minted-novel-token-8842"),
            "got {out:?}"
        );
        assert!(
            out.contains("AWS_SESSION_TOKEN=") && out.contains("REDACTED"),
            "key is preserved and the value redacted, got {out:?}"
        );
    }

    #[test]
    #[cfg(windows)]
    fn windows_render_body_claude_mode_scrubs_table_known_secret_in_error_marker() {
        let cfg = RedactConfig {
            denylist: vec!["TABLESTDERRSECRET7".to_string()],
            scan_ssh_keys: false,
            ..Default::default()
        };
        let redact = RedactionTable::build(&cfg, Path::new("/")).unwrap();
        let body = "x !`Write-Error TABLESTDERRSECRET7; exit 1` y";
        let out = render_body(body, Path::new("."), true, false, &redact);
        assert!(!out.contains("TABLESTDERRSECRET7"), "got {out:?}");
        assert!(out.contains("[skill command"), "got {out:?}");
    }

    #[test]
    #[cfg(windows)]
    fn windows_render_body_claude_mode_redacts_novel_secret_in_error_marker_stderr() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("err.env"),
            "DB_PASSWORD=novel-stderr-secret-77aa\n",
        )
        .unwrap();
        let body = "x !`$s = Get-Content err.env; [Console]::Error.WriteLine($s); exit 1` y";
        let out = render_body(body, tmp.path(), true, false, &no_redact());
        assert!(!out.contains("novel-stderr-secret-77aa"), "got {out:?}");
        assert!(out.contains("[skill command"), "got {out:?}");
        assert!(
            out.contains("DB_PASSWORD=") && out.contains("REDACTED"),
            "key is preserved and the value redacted, got {out:?}"
        );
    }

    #[test]
    fn render_body_keeps_bang_directives_verbatim_behind_knowledge_write_fence() {
        let body = "value: !`echo must-not-run`";
        let out = trusted_render_body(body, Path::new("."), true, &no_redact());
        assert_eq!(out, "value: must-not-run");

        let fenced = render_body(body, Path::new("."), true, true, &no_redact());
        assert_eq!(fenced, body);
    }

    #[test]
    fn catalog_lines_is_name_description_only() {
        let skills = vec![
            Skill {
                frontmatter: SkillFrontmatter {
                    name: "a".into(),
                    description: "first".into(),
                    ..Default::default()
                },
                source: PathBuf::from("/x/a/SKILL.md"),
            },
            Skill {
                frontmatter: SkillFrontmatter {
                    name: "b".into(),
                    description: "second".into(),
                    ..Default::default()
                },
                source: PathBuf::from("/x/b/SKILL.md"),
            },
        ];
        let cat = catalog_lines(&skills);
        assert_eq!(cat, "- a: first\n- b: second\n");
    }

    #[test]
    fn package_root_is_skill_md_parent() {
        let skill = Skill {
            frontmatter: SkillFrontmatter {
                name: "package-root".into(),
                description: "package root test".into(),
                ..Default::default()
            },
            source: PathBuf::from("/x/package-root/SKILL.md"),
        };
        assert_eq!(package_root(&skill), Path::new("/x/package-root"));

        let parentless = Skill {
            frontmatter: SkillFrontmatter {
                name: "parentless".into(),
                description: "parentless source test".into(),
                ..Default::default()
            },
            source: PathBuf::from("/"),
        };
        assert_eq!(package_root(&parentless), Path::new("/"));
    }

    #[test]
    fn package_target_for_path_classifies_manifest_support_and_outside() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join(".agents").join("skills");
        write_skill(
            &scan,
            "target",
            "---\nname: target\ndescription: d\n---\n",
            "Body",
        );
        let cfg = skills_cfg(vec![".agents/skills"], false);
        let package = scan.join("target");

        let manifest =
            trusted_package_target_for_path(&package.join("SKILL.md"), tmp.path(), &cfg).unwrap();
        assert_eq!(manifest.name, "target");
        assert_eq!(manifest.package_root, package);
        assert!(manifest.is_manifest);
        assert_eq!(manifest.relative_path, Path::new("SKILL.md"));

        let support = trusted_package_target_for_path(
            &package.join("references").join("a.md"),
            tmp.path(),
            &cfg,
        )
        .unwrap();
        assert_eq!(support.name, "target");
        assert!(!support.is_manifest);
        assert_eq!(support.relative_path, Path::new("references/a.md"));

        assert!(
            trusted_package_target_for_path(&tmp.path().join("outside.md"), tmp.path(), &cfg)
                .is_none()
        );
    }

    #[test]
    fn package_target_for_path_rejects_prefix_lookalike() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("skills");
        write_skill(
            &scan,
            "target",
            "---\nname: target\ndescription: d\n---\n",
            "Body",
        );
        let lookalike = tmp.path().join("skills-other").join("target");
        std::fs::create_dir_all(&lookalike).unwrap();
        let cfg = skills_cfg(vec!["skills"], false);

        assert!(package_target_for_path(&lookalike.join("SKILL.md"), tmp.path(), &cfg).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn package_target_for_path_handles_canonical_workspace_alias() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let scan = workspace.join(".agents").join("skills");
        write_skill(
            &scan,
            "target",
            "---\nname: target\ndescription: d\n---\n",
            "Body",
        );
        let alias = tmp.path().join("workspace-alias");
        symlink(&workspace, &alias).unwrap();
        let cfg = skills_cfg(vec![".agents/skills"], false);

        let target =
            crate::config::trust::with_workspace_trust_policy(trusted_policy(&alias), || {
                package_target_for_path(&alias.join(".agents/skills/target/SKILL.md"), &alias, &cfg)
            })
            .expect("workspace aliases should still identify managed skill packages");

        assert_eq!(target.name, "target");
    }

    #[test]
    fn managed_skill_write_rejects_traversal_that_normalizes_into_package() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join(".agents").join("skills");
        write_skill(
            &scan,
            "target",
            "---\nname: target\ndescription: d\n---\n",
            "Body",
        );
        let cfg = skills_cfg(vec![".agents/skills"], false);
        let effective = scan.join("target/references/a.md");
        let relative = Path::new("outside/../.agents/skills/target/references/a.md");
        let absolute = tmp
            .path()
            .join("unrelated/../.agents/skills/target/references/a.md");

        for requested in [relative, absolute.as_path()] {
            let error = crate::config::trust::with_workspace_trust_policy(
                trusted_policy(tmp.path()),
                || {
                    validate_skill_package_write_for_paths(
                        requested,
                        &effective,
                        tmp.path(),
                        &cfg,
                        "reference",
                    )
                },
            )
            .unwrap_err();
            assert!(error.to_string().contains("parent traversal"), "{error:#}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn managed_skill_write_rejects_outside_symlink_then_parent_traversal() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join(".agents").join("skills");
        write_skill(
            &scan,
            "target",
            "---\nname: target\ndescription: d\n---\n",
            "Body",
        );
        let references = scan.join("target/references");
        std::fs::create_dir_all(&references).unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        symlink(&references, outside.join("into-managed")).unwrap();

        let cfg = skills_cfg(vec![".agents/skills"], false);
        let requested = outside.join("into-managed/../SKILL.md");
        let effective = scan.join("target/SKILL.md");
        let error =
            crate::config::trust::with_workspace_trust_policy(trusted_policy(tmp.path()), || {
                validate_skill_package_write_for_paths(
                    &requested,
                    &effective,
                    tmp.path(),
                    &cfg,
                    "replacement",
                )
            })
            .unwrap_err();

        assert!(error.to_string().contains("parent traversal"), "{error:#}");
    }

    #[test]
    fn ordinary_write_with_parent_segment_is_not_treated_as_skill_write() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join(".agents").join("skills");
        write_skill(
            &scan,
            "target",
            "---\nname: target\ndescription: d\n---\n",
            "Body",
        );
        let cfg = skills_cfg(vec![".agents/skills"], false);
        let requested = Path::new("outside/../plain.md");
        let effective = tmp.path().join("plain.md");

        let validation =
            crate::config::trust::with_workspace_trust_policy(trusted_policy(tmp.path()), || {
                validate_skill_package_write_for_paths(
                    requested,
                    &effective,
                    tmp.path(),
                    &cfg,
                    "ordinary",
                )
            })
            .unwrap();

        assert!(validation.is_none());
    }

    #[test]
    fn model_invocable_lookup_rejects_user_only_skill() {
        let skills = vec![Skill {
            frontmatter: SkillFrontmatter {
                name: "manual".into(),
                description: "Manual only".into(),
                disable_model_invocation: true,
                ..Default::default()
            },
            source: PathBuf::from("/x/manual/SKILL.md"),
        }];

        assert!(find_by_name(&skills, "manual").is_some());
        assert!(find_model_invocable_by_name(&skills, "manual").is_none());
    }

    #[test]
    fn model_invocation_filter_is_shared_by_both_paths() {
        let model_skill = Skill {
            frontmatter: SkillFrontmatter {
                name: "model".into(),
                description: "Model visible".into(),
                ..Default::default()
            },
            source: PathBuf::from("/x/model/SKILL.md"),
        };
        let user_only = Skill {
            frontmatter: SkillFrontmatter {
                name: "manual".into(),
                description: "Manual only".into(),
                disable_model_invocation: true,
                ..Default::default()
            },
            source: PathBuf::from("/x/manual/SKILL.md"),
        };
        let skills = vec![model_skill, user_only];

        let catalog = catalog_lines(skills.iter().filter(|skill| is_model_invocable(skill)));

        assert!(find_model_invocable_by_name(&skills, "model").is_some());
        assert!(find_model_invocable_by_name(&skills, "manual").is_none());
        assert!(catalog.contains("- model: Model visible"));
        assert!(!catalog.contains("manual"));
    }

    #[test]
    fn agentskills_package_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("skills");
        write_skill(
            &scan,
            "research",
            "---\nname: research\ndescription: Research workflow\nversion: 1.0.0\n---\n",
            "Read references/foo.md on demand.",
        );
        let package = scan.join("research");
        std::fs::create_dir_all(package.join("references")).unwrap();
        std::fs::write(package.join("references/foo.md"), "Reference details").unwrap();
        let cfg = skills_cfg(vec![scan.to_str().unwrap()], false);

        let found = trusted_discover(tmp.path(), &cfg).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(
            load_body(&found[0]).unwrap(),
            "Read references/foo.md on demand."
        );
        assert_eq!(
            load_support_file(&found[0], Path::new("references/foo.md")).unwrap(),
            "Reference details"
        );
    }

    #[test]
    fn support_file_path_allowlisted() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("skills");
        write_skill(
            &scan,
            "safe-package",
            "---\nname: safe-package\ndescription: Safe package\n---\n",
            "Body",
        );
        let package = scan.join("safe-package");
        std::fs::create_dir_all(package.join("references")).unwrap();
        std::fs::create_dir_all(package.join("docs")).unwrap();
        std::fs::write(package.join("references/ok.md"), "ok").unwrap();
        std::fs::write(package.join("docs/no.md"), "no").unwrap();
        let skill = parse_skill(&package.join("SKILL.md")).unwrap();

        assert_eq!(
            load_support_file(&skill, Path::new("references/ok.md")).unwrap(),
            "ok"
        );
        assert!(load_support_file(&skill, Path::new("references/../SKILL.md")).is_err());
        assert!(load_support_file(&skill, Path::new("docs/no.md")).is_err());
        assert!(load_support_file(&skill, Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn conditional_activation_matrix() {
        let skill = Skill {
            frontmatter: SkillFrontmatter {
                name: "conditional".into(),
                description: "Conditional".into(),
                platforms: vec!["linux".into()],
                metadata: SkillMetadata {
                    hermes: HermesMetadata {
                        requires_toolsets: vec!["web".into()],
                        fallback_for_toolsets: vec!["browser".into()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            source: PathBuf::from("/skills/conditional/SKILL.md"),
        };
        let mut active = ActivationContext::from_tool_names(["websearch"]);
        active.platform = "linux".into();
        assert!(skill_is_active(&skill, &active));

        let missing_required = ActivationContext {
            platform: "linux".into(),
            ..Default::default()
        };
        assert!(!skill_is_active(&skill, &missing_required));

        active.toolsets.insert("browser".into());
        assert!(!skill_is_active(&skill, &active));
        active.toolsets.remove("browser");
        active.platform = "windows".into();
        assert!(!skill_is_active(&skill, &active));
    }

    #[test]
    fn hermes_metadata_mapped() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("mapped").join("SKILL.md");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "---\nname: mapped\ndescription: Mapped metadata\nversion: 2.1.0\nplatforms: [linux]\nmetadata:\n  hermes:\n    category: research\n    tags: [web, sources]\n    requires_toolsets: [web]\n    fallback_for_tools: [browser_navigate]\n    config:\n      - key: web.region\n        default: us\nrequired_environment_variables:\n  - name: SEARCH_API_KEY\n    prompt: Search key\n---\nBody",
        )
        .unwrap();
        let skill = parse_skill(&path).unwrap();
        let hermes = &skill.frontmatter.metadata.hermes;
        assert_eq!(skill.frontmatter.version.as_deref(), Some("2.1.0"));
        assert_eq!(skill.frontmatter.platforms, ["linux"]);
        assert_eq!(hermes.category.as_deref(), Some("research"));
        assert_eq!(hermes.tags, ["web", "sources"]);
        assert_eq!(hermes.requires_toolsets, ["web"]);
        assert_eq!(hermes.fallback_for_tools, ["browser_navigate"]);
        assert_eq!(hermes.config[0].key, "web.region");
        assert_eq!(
            skill.frontmatter.required_environment_variables[0].name,
            "SEARCH_API_KEY"
        );
    }

    #[test]
    fn unknown_keys_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("future").join("SKILL.md");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "---\nname: future\ndescription: Future metadata\nfuture_top: yes\nmetadata:\n  future_metadata: 7\n  hermes:\n    future_hermes: enabled\n---\nBody",
        )
        .unwrap();
        let skill = parse_skill(&path).unwrap();
        assert!(skill.frontmatter.extra.contains_key("future_top"));
        assert!(
            skill
                .frontmatter
                .metadata
                .extra
                .contains_key("future_metadata")
        );
        assert!(
            skill
                .frontmatter
                .metadata
                .hermes
                .extra
                .contains_key("future_hermes")
        );
    }

    #[test]
    fn external_dirs_scanned() {
        let tmp = tempfile::tempdir().unwrap();
        let external = tmp.path().join("hermes-skills");
        write_skill(
            &external.join("research"),
            "shared",
            "---\nname: shared\ndescription: Shared package\n---\n",
            "Body",
        );
        let cfg = SkillsConfig {
            external_dirs: vec![external.to_string_lossy().into_owned()],
            ..Default::default()
        };
        let found = trusted_discover(tmp.path(), &cfg).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].frontmatter.name, "shared");
        assert!(
            found[0]
                .source
                .ends_with("hermes-skills/research/shared/SKILL.md")
        );
    }

    #[cfg(unix)]
    #[test]
    fn recursive_discovery_ignores_symlink_escape_and_loop() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let external = tmp.path().join("external");
        let outside = tmp.path().join("outside");
        write_skill(
            &outside,
            "escaped",
            "---\nname: escaped\ndescription: Must not load\n---\n",
            "Body",
        );
        std::fs::create_dir_all(external.join("category")).unwrap();
        symlink(&outside, external.join("category/escape-link")).unwrap();
        symlink(&external, external.join("category/loop-link")).unwrap();
        let manifest_link_package = external.join("category/manifest-link");
        std::fs::create_dir_all(&manifest_link_package).unwrap();
        symlink(
            outside.join("escaped/SKILL.md"),
            manifest_link_package.join("SKILL.md"),
        )
        .unwrap();
        write_skill(
            &external.join(".hub/quarantine"),
            "quarantined",
            "---\nname: quarantined\ndescription: Must not load\n---\n",
            "Body",
        );
        symlink(
            external.join(".hub/quarantine"),
            external.join("category/visible-quarantine-link"),
        )
        .unwrap();
        write_skill(
            &external.join("category"),
            "inside",
            "---\nname: inside\ndescription: Loads\n---\n",
            "Body",
        );
        let cfg = SkillsConfig {
            external_dirs: vec![external.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let found = trusted_discover(tmp.path(), &cfg).unwrap();
        let names: Vec<&str> = found
            .iter()
            .map(|skill| skill.frontmatter.name.as_str())
            .collect();
        assert_eq!(names, ["inside"]);
    }

    #[test]
    fn agent_inventory_filters_incompatible_skills() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("skills");
        write_skill(
            &scan,
            "plain",
            "---\nname: plain\ndescription: Always visible\n---\n",
            "Body",
        );
        write_skill(
            &scan,
            "needs-web",
            "---\nname: needs-web\ndescription: Web only\nmetadata:\n  hermes:\n    requires_toolsets: [web]\n---\n",
            "Body",
        );
        let cfg = SkillsConfig {
            scan_dirs: vec![scan.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let found =
            crate::config::trust::with_workspace_trust_policy(trusted_policy(tmp.path()), || {
                discover_for_agent(tmp.path(), &cfg, "agent-that-does-not-exist")
            })
            .unwrap();
        let names: Vec<&str> = found
            .iter()
            .map(|skill| skill.frontmatter.name.as_str())
            .collect();
        assert_eq!(names, ["plain"]);
    }

    #[test]
    fn cockpit_skills_are_conformant() {
        let tmp = tempfile::tempdir().unwrap();
        let scan = tmp.path().join("skills");
        write_skill(
            &scan,
            "cockpit-authored",
            "---\nname: cockpit-authored\ndescription: A conformant Cockpit-authored package\n---\n",
            "Body",
        );
        let skill = parse_skill(&scan.join("cockpit-authored/SKILL.md")).unwrap();
        validate_conformant_package(&skill).unwrap();
    }

    #[test]
    fn catalog_description_is_capped_without_truncating_manifest() {
        let full = "This description is intentionally much longer than sixty characters so only the catalog copy is shortened";
        let skill = Skill {
            frontmatter: SkillFrontmatter {
                name: "long".into(),
                description: full.into(),
                ..Default::default()
            },
            source: PathBuf::from("/skills/long/SKILL.md"),
        };
        let catalog = catalog_lines(std::slice::from_ref(&skill));
        let rendered = catalog.trim_start_matches("- long: ").trim_end();
        assert!(rendered.chars().count() <= MAX_CATALOG_DESCRIPTION_CHARS);
        assert!(rendered.ends_with('…'));
        assert_eq!(skill.frontmatter.description, full);
    }
}
