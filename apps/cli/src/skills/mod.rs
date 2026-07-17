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
//!     [`crate::redact::RedactionTable::scrub`] (non-bypassable, GOALS
//!     §7) before it enters context. A nonzero exit / spawn failure
//!     injects a clear inline error marker rather than crashing the turn.
//!   - **Codex mode (disabled, the default):** the `` !`command` ``
//!     directive is left verbatim — the model sees the literal text and
//!     the command never runs.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::extended::SkillsConfig;
use crate::redact::RedactionTable;

pub mod auto_select;

const MAX_MARKDOWN_BYTES: u64 = 1024 * 1024;
const MAX_CATALOG_DESCRIPTION_CHARS: usize = 60;
const SUPPORT_DIRS: [&str; 4] = ["references", "templates", "scripts", "assets"];

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
    let mut skills: Vec<Skill> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for dir in dirs {
        for manifest in manifests_under(&dir) {
            match parse_skill(&manifest) {
                Ok(skill) => {
                    if seen.insert(skill.frontmatter.name.clone()) {
                        skills.push(skill);
                    }
                }
                Err(e) => {
                    tracing::warn!(path = %manifest.display(), error = %e, "skipping malformed SKILL.md");
                }
            }
        }
    }

    Ok(skills)
}

/// Return every package manifest beneath one configured root in deterministic
/// path order. Category directories used by Hermes are traversed recursively;
/// once a package manifest is found its support directories are not searched
/// for nested packages. Canonical-root checks plus a visited set prevent
/// symlink escapes and loops.
fn manifests_under(root: &Path) -> Vec<PathBuf> {
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

    let package = skill
        .source
        .parent()
        .context("SKILL.md has no package directory")?
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
    let len = std::fs::metadata(path)
        .with_context(|| format!("statting {}", path.display()))?
        .len();
    if len > MAX_MARKDOWN_BYTES {
        tracing::warn!(
            path = %path.display(),
            size = len,
            limit = MAX_MARKDOWN_BYTES,
            "skipping oversized SKILL.md"
        );
        anyhow::bail!(
            "SKILL.md exceeds {} byte limit: {}",
            MAX_MARKDOWN_BYTES,
            path.display()
        );
    }
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
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
    let after_open = match rest.find('\n') {
        Some(nl) => {
            // Ensure the opening line is *only* `---` (allow trailing CR).
            let first_line = rest[..nl].trim_end_matches('\r');
            if first_line != "---" {
                return None;
            }
            &rest[nl + 1..]
        }
        None => return None,
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
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in &cfg.scan_dirs {
        resolve_dir_entry(entry, cwd, cfg.ancestor_walk, &mut out);
    }
    for entry in &cfg.external_dirs {
        resolve_dir_entry(entry, cwd, false, &mut out);
    }
    out.into_iter()
        .filter(|dir| skill_scan_dir_allowed_by_trust(dir))
        .collect()
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
/// before it enters context (GOALS §7). In Codex mode (`auto_bang_commands
/// == false`) directives are returned verbatim and no command runs.
pub fn render_body(
    body: &str,
    cwd: &Path,
    auto_bang_commands: bool,
    redact: &RedactionTable,
) -> String {
    if !auto_bang_commands || crate::config::trust::path_blocked_by_workspace_trust(cwd) {
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

/// Run one inline `!`-command and return the (redacted) stdout, or a
/// bracketed error marker on failure / nonzero exit. Never panics.
fn run_bang_command(cmd: &str, cwd: &Path, _redact: &RedactionTable) -> String {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return "[skill command error: empty command]".to_string();
    }
    let (shell, shell_arg) = bang_command_shell();
    let output = Command::new(shell)
        .arg(shell_arg)
        .arg(trimmed)
        .current_dir(cwd)
        .output();
    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // Trim the trailing newline command stdout usually carries so
            // the substitution reads inline-naturally; redact before it
            // enters context.
            stdout.trim_end_matches('\n').to_string()
        }
        Ok(out) => {
            let code = out
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signaled".to_string());
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stderr = stderr.trim().to_string();
            if stderr.is_empty() {
                format!("[skill command `{trimmed}` failed: exit {code}]")
            } else {
                format!("[skill command `{trimmed}` failed: exit {code}: {stderr}]")
            }
        }
        Err(e) => format!("[skill command `{trimmed}` failed to run: {e}]"),
    }
}

#[cfg(windows)]
fn bang_command_shell() -> (&'static str, &'static str) {
    ("cmd", "/C")
}

#[cfg(not(windows))]
fn bang_command_shell() -> (&'static str, &'static str) {
    ("sh", "-c")
}

/// Locate a discovered skill by exact `name`. Used by the `skill` tool's
/// manual-invocation path.
pub fn find_by_name<'a>(skills: &'a [Skill], name: &str) -> Option<&'a Skill> {
    skills.iter().find(|s| s.frontmatter.name == name)
}

/// Build the cheap-model catalog string: one `- name: description` line
/// per skill. This is the only payload the utility model ever sees for
/// selection (token economy, GOALS §10) — never a body.
pub fn catalog_lines(skills: &[Skill]) -> String {
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
        };
        let found = discover(tmp.path(), &cfg).unwrap();
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
        };
        let found = discover(tmp.path(), &cfg).unwrap();
        let names: Vec<&str> = found.iter().map(|s| s.frontmatter.name.as_str()).collect();
        assert_eq!(names, vec!["ok"], "only the well-formed skill survives");
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
        };
        let found = discover(tmp.path(), &cfg).unwrap();
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
        };
        let found = discover(tmp.path(), &cfg).unwrap();

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
        }
    }

    #[test]
    fn resolve_scan_dirs_expands_env_and_relative() {
        let cwd = Path::new("/tmp/project");
        // Relative resolves against cwd; absolute stays absolute.
        let cfg = skills_cfg(vec!["skills/dir", "/abs/skills"], false);
        let dirs = resolve_scan_dirs(cwd, &cfg);
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
        // SAFETY: single-threaded test; we set then read a unique var.
        unsafe {
            std::env::set_var("COCKPIT_TEST_SKILLS_ROOT", "/var/skills");
        }
        let cfg = skills_cfg(vec!["$COCKPIT_TEST_SKILLS_ROOT/sub"], false);
        let dirs = resolve_scan_dirs(Path::new("/cwd"), &cfg);
        assert_eq!(dirs, vec![PathBuf::from("/var/skills/sub")]);
        unsafe {
            std::env::remove_var("COCKPIT_TEST_SKILLS_ROOT");
        }
    }

    #[test]
    fn resolve_scan_dirs_empty_yields_no_dirs() {
        // No implicit fallback: an empty list scans nothing.
        let cfg = skills_cfg(vec![], false);
        assert!(resolve_scan_dirs(Path::new("/tmp/project"), &cfg).is_empty());
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
        let dirs_off = resolve_scan_dirs(&nested, &off);
        assert_eq!(dirs_off, vec![nested.join(".agents").join("skills")]);

        // Ancestor walk ON: cwd plus every ancestor up to and including
        // the worktree root.
        let on = skills_cfg(vec![".agents/skills"], true);
        let dirs_on = resolve_scan_dirs(&nested, &on);
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
        let dirs = resolve_scan_dirs(Path::new("/tmp/a/b"), &cfg);
        assert_eq!(dirs, vec![PathBuf::from("/abs/skills")]);
    }

    #[test]
    fn render_body_codex_mode_injects_verbatim() {
        let body = "before !`echo hi` after";
        let out = render_body(body, Path::new("."), false, &no_redact());
        assert_eq!(out, body, "Codex mode leaves the directive verbatim");
    }

    #[test]
    fn render_body_claude_mode_runs_command() {
        let body = "value: !`echo hello`";
        let out = render_body(body, Path::new("."), true, &no_redact());
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
            render_body(body, tmp.path(), true, &no_redact())
        });

        assert_eq!(out, body);
    }

    #[test]
    #[cfg(not(windows))]
    fn bang_command_shell_uses_sh_on_unix_like_platforms() {
        assert_eq!(bang_command_shell(), ("sh", "-c"));
    }

    #[test]
    #[cfg(windows)]
    fn bang_command_shell_uses_cmd_on_windows() {
        assert_eq!(bang_command_shell(), ("cmd", "/C"));
    }

    #[test]
    fn render_body_claude_mode_error_marker_on_failure() {
        let body = "x !`exit 3` y";
        let out = render_body(body, Path::new("."), true, &no_redact());
        assert!(
            out.contains("[skill command") && out.contains("exit 3"),
            "expected an inline error marker, got {out:?}"
        );
        // The turn never crashes — surrounding text survives.
        assert!(out.starts_with("x ") && out.ends_with(" y"));
    }

    #[test]
    fn render_body_claude_mode_keeps_command_output_raw_until_dispatch() {
        // Command output remains raw locally; model dispatch applies the
        // dispatching model's effective redaction table.
        let cfg = RedactConfig {
            denylist: vec!["SUPERSECRETTOKEN".to_string()],
            scan_ssh_keys: false,
            ..Default::default()
        };
        let redact = RedactionTable::build(&cfg, Path::new("/")).unwrap();
        let body = "leak: !`echo SUPERSECRETTOKEN`";
        let out = render_body(body, Path::new("."), true, &redact);
        assert!(out.contains("SUPERSECRETTOKEN"), "got {out:?}");
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

        let found = discover(tmp.path(), &cfg).unwrap();
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

        let mut missing_required = ActivationContext::default();
        missing_required.platform = "linux".into();
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
        let found = discover(tmp.path(), &cfg).unwrap();
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

        let found = discover(tmp.path(), &cfg).unwrap();
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

        let found = discover_for_agent(tmp.path(), &cfg, "agent-that-does-not-exist").unwrap();
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
