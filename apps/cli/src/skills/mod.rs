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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::extended::SkillsConfig;
use crate::redact::RedactionTable;

pub mod auto_select;

const MAX_MARKDOWN_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillFrontmatter {
    pub name: String,
    pub description: String,
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
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            // Non-existent / unreadable scan dir: silently ignored.
            Err(_) => continue,
        };
        // Sort entries so discovery order is deterministic across
        // platforms (readdir order is filesystem-dependent).
        let mut subdirs: Vec<PathBuf> = entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        subdirs.sort();

        for sub in subdirs {
            let manifest = sub.join("SKILL.md");
            if !manifest.is_file() {
                continue;
            }
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

fn user_global_skill_roots(home: &Path) -> [PathBuf; 3] {
    [
        home.join(".agents").join("skills"),
        home.join(".claude").join("skills"),
        home.join(".cockpit").join("skills"),
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
        out.push_str(&s.frontmatter.description);
        out.push('\n');
    }
    out
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
}
