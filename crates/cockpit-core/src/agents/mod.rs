//! Agent definition discovery, parsing, resolution, and invariant
//! validation.
//!
//! On-disk format: YAML frontmatter + Markdown body. The frontmatter shape
//! is inspired by opencode's agent files (we own the file layout but
//! the field names track theirs where the design is good — see
//! `the CLI design notes` §4 for the schema).
//!
//! ```text
//! ---
//! description: One-line description.
//! mode: subagent
//! model: anthropic/claude-opus-4-7
//! temperature: 0.2
//! tools: [read, bash, search]
//! ---
//! <markdown body == the agent's system prompt>
//! ```
//!
//! Disk model (implementation note): the bundled cast
//! (`Build`, `builder`, `explore`) stays **embedded** in the binary as
//! fallback [`AgentDef`]s. Nothing is written on first run. "Editing" a
//! built-in *ejects* its default to `.cockpit/agents/<name>.md`; from then
//! on the on-disk file overrides the embedded default **by name**.
//! "Reset" deletes the override. Custom agents (any non-built-in name)
//! live only on disk and are never touched by reset.
//!
//! The docs two-stage pipeline (Docs.1 / Docs.2) is **not** an [`AgentDef`]
//! — it stays entirely hardcoded in [`crate::engine::builtin`] and
//! [`crate::engine::docs_pipeline`] and is never exposed here.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

mod builtin_defs;
pub(crate) mod invariants;

pub use builtin_defs::{
    BUILTIN_AGENT_NAMES, FALLBACK_PRIMARY, embedded_default, is_builtin_agent,
    is_experimental_primary, is_hidden_primary, resolve_primary_for_flag,
};
pub use invariants::validate_invariants;

const MAX_MARKDOWN_BYTES: u64 = 1024 * 1024;

/// A fully-resolved agent definition: the embedded default for a
/// built-in, or a user-authored file on disk. The `model`/`temperature`/
/// `tools` here are what the engine builds the agent from — an edited
/// override therefore takes effect on the next agent run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDef {
    /// The agent's name. Not part of the frontmatter — it is the file
    /// stem (`<name>.md` or the `<name>/` directory). Carried here for
    /// dispatch and override-by-name resolution.
    #[serde(skip)]
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub mode: AgentMode,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub tools: Option<Vec<String>>,
    /// Per-agent tool-description overrides (prompt
    /// `per-agent-tool-definitions.md`): re-word a granted tool's *description*
    /// for **this** agent without touching its ID or schema, so the same tool
    /// can encode different per-agent intent (e.g. `Build` "delegate-eager" vs
    /// a "do-it-yourself" primary). Keyed by tool name; the value carries the
    /// per-`llm_mode` text (a bare string applies to all modes). Applied at
    /// [`crate::engine::builtin`] construction time onto the toolbox via
    /// [`crate::engine::tool::ToolBox::with_override`] — fixed at session
    /// start, so the tools array stays byte-stable (cache-safe). Empty / absent
    /// means every tool keeps its base description (byte-identical to today).
    #[serde(default)]
    pub tool_descriptions: std::collections::BTreeMap<String, ToolDescriptionSpec>,
    /// Whether this agent's untrusted tool/subagent results are scanned by the
    /// prompt-injection guard before entering parent history. `None` means use
    /// the role/name default.
    #[serde(rename = "scanToolResults", default)]
    pub scan_tool_results: Option<bool>,
    #[serde(default)]
    pub permission: Option<serde_json::Value>,
    /// Body of the markdown file (the agent's system prompt). Resolved
    /// through [`AgentDef::resolved_prompt`] / [`AgentDef::resolved_prompt_for`]
    /// rather than read directly so the per-`llm_mode` body variant threads
    /// through one path (implementation note). For a
    /// flat-file agent (single-mode) this is *the* body, used for every mode.
    /// For a per-mode directory agent it holds the body that was selected at
    /// load time (and [`Self::prompt_variants`] carries the per-mode bodies).
    #[serde(skip)]
    pub prompt: String,
    /// Per-`llm_mode` prompt bodies for a directory-form agent
    /// (`<dir>/<name>/<mode>.md`). Empty for a flat-file or embedded agent
    /// (single-mode — [`Self::prompt`] applies to every mode). When present,
    /// [`Self::resolved_prompt_for`] selects the body matching the active
    /// mode, falling back to [`Self::prompt`] (the flat body) when the
    /// requested mode's file was absent. `frontier` first falls back to the
    /// `normal` body when present, then to the flat body.
    #[serde(skip)]
    pub prompt_variants: std::collections::HashMap<crate::config::extended::LlmMode, String>,
    /// Path the definition was loaded from (`<dir>/<name>.md` or the
    /// `<dir>/<name>/` directory), or empty for an embedded default. Used
    /// for diagnostics and override detection.
    #[serde(skip)]
    pub source: PathBuf,
}

/// A markdown agent's per-agent description override for one tool (prompt
/// `per-agent-tool-definitions.md`). Authored in `tool_descriptions:`
/// frontmatter in either of two forms:
///
/// ```yaml
/// tool_descriptions:
///   # bare string → applies to all llm_modes
///   read: "Skim before delegating — you don't write."
///   # per-mode object → distinct normal/frontier/defensive text (each optional)
///   task:
///     normal: "Delegate substantive work here."
///     frontier: "Delegate only clearly separable work."
///     defensive: "Hand each well-scoped piece to a subagent …"
/// ```
///
/// Only the *description text* is selected; the tool's ID and SCHEMA are
/// never affected (schema variation would change validation/repair behavior).
///
/// Deserialization is hand-written (a [`serde::de::Visitor`]) rather than
/// `#[serde(untagged)]`: serde_yaml 0.9's untagged path mishandles a
/// newtype-string-vs-struct mix, silently producing an empty map. The visitor
/// accepts a scalar string ([`Self::Both`]) or a `{normal, defensive}` map
/// ([`Self::PerMode`]) directly, so it works under both YAML and JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolDescriptionSpec {
    /// One string used for every mode.
    Both(String),
    /// Distinct per-mode text; either field may be omitted to fall back to the
    /// tool's own base description for that mode.
    PerMode {
        normal: Option<String>,
        frontier: Option<String>,
        defensive: Option<String>,
    },
}

impl Serialize for ToolDescriptionSpec {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            ToolDescriptionSpec::Both(text) => ser.serialize_str(text),
            ToolDescriptionSpec::PerMode {
                normal,
                frontier,
                defensive,
            } => {
                let len = normal.is_some() as usize
                    + frontier.is_some() as usize
                    + defensive.is_some() as usize;
                let mut map = ser.serialize_map(Some(len))?;
                if let Some(n) = normal {
                    map.serialize_entry("normal", n)?;
                }
                if let Some(f) = frontier {
                    map.serialize_entry("frontier", f)?;
                }
                if let Some(d) = defensive {
                    map.serialize_entry("defensive", d)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for ToolDescriptionSpec {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> std::result::Result<Self, D::Error> {
        struct SpecVisitor;
        impl<'de> serde::de::Visitor<'de> for SpecVisitor {
            type Value = ToolDescriptionSpec;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a description string or a `{normal, frontier, defensive}` map")
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(ToolDescriptionSpec::Both(v.to_string()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(ToolDescriptionSpec::Both(v))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut normal: Option<String> = None;
                let mut frontier: Option<String> = None;
                let mut defensive: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "normal" => normal = map.next_value()?,
                        "frontier" => frontier = map.next_value()?,
                        "defensive" => defensive = map.next_value()?,
                        other => {
                            return Err(serde::de::Error::custom(format!(
                                "unknown tool-description key `{other}` (expected `normal`, `frontier`, or `defensive`)"
                            )));
                        }
                    }
                }
                Ok(ToolDescriptionSpec::PerMode {
                    normal,
                    frontier,
                    defensive,
                })
            }
        }
        de.deserialize_any(SpecVisitor)
    }
}

impl ToolDescriptionSpec {
    /// Project to the engine-level [`crate::engine::tool::ToolDescOverride`].
    /// A bare string fans out to every mode; the per-mode form maps straight
    /// across.
    pub fn to_override(&self) -> crate::engine::tool::ToolDescOverride {
        match self {
            ToolDescriptionSpec::Both(text) => crate::engine::tool::ToolDescOverride {
                normal: Some(text.clone()),
                frontier: Some(text.clone()),
                defensive: Some(text.clone()),
            },
            ToolDescriptionSpec::PerMode {
                normal,
                frontier,
                defensive,
            } => crate::engine::tool::ToolDescOverride {
                normal: normal.clone(),
                frontier: frontier.clone(),
                defensive: defensive.clone(),
            },
        }
    }
}

/// Reachability of an agent in the delegation tree. **Not** the
/// defensive/normal LLM-mode axis (that future feature owns a separate
/// key — see implementation note forward-compat notes);
/// do not overload this.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    /// Reachable both as a primary (chat-owning) agent and as a `task`
    /// subagent.
    #[default]
    All,
    /// Reachable only as a primary chat-owning agent.
    Primary,
    /// Reachable only as a `task` subagent.
    Subagent,
}

impl AgentMode {
    /// Whether this agent may be delegated to via `task` (i.e. it is a
    /// reachable subagent). The `Primary`/`All` distinction for chat
    /// ownership is consumed by the future LLM-modes work; only subagent
    /// reachability is load-bearing today.
    pub fn is_subagent(self) -> bool {
        matches!(self, AgentMode::All | AgentMode::Subagent)
    }

    /// Whether this agent may own the chat as a primary (top-level) agent —
    /// i.e. it is a valid `/agent` switch / `Shift+Tab` cycle target. `All`
    /// and `Primary` are chat-ownable; a `Subagent` is never. The inverse of
    /// "subagent-only" (`builder`/`explore`/`docs`).
    pub fn is_chat_ownable(self) -> bool {
        matches!(self, AgentMode::All | AgentMode::Primary)
    }
}

/// The chat-owning (primary) agents in their canonical cycle / listing
/// order: the five builtins first (`Auto`, `Plan`, `Build`, `Swarm`,
/// `Plan`), then every
/// user-defined chat-ownable agent (mode `primary` or `all`, excluding the
/// builtins) in alphabetical order by name. Drives both the `/agent` valid-
/// choices list and the `Shift+Tab` cycle (`agent-switch-command-
/// and-cycle.md`). Custom agents whose file failed to parse are skipped —
/// they cannot be resolved as a switch target. Subagents are never included.
pub fn chat_ownable_primaries(cwd: &Path) -> Vec<String> {
    // Experimental-mode gate (implementation note): read the
    // flag from the layered config, then delegate. Split so the flag-driven
    // filtering is unit-testable without a config layer winning the
    // discovery walk.
    let experimental = crate::config::extended::load_for_cwd(cwd).experimental_mode;
    chat_ownable_primaries_with(cwd, experimental)
}

/// [`chat_ownable_primaries`] with the experimental flag supplied directly
/// (the production entry reads it via `load_for_cwd`). With `experimental`
/// off the gated builtins (`Auto`/`Plan`/`Swarm`) are fully
/// hidden — only `Build` (and user customs) remains; this one filter
/// cascades to every consumer of the chat-ownable list.
fn chat_ownable_primaries_with(cwd: &Path, experimental: bool) -> Vec<String> {
    // Builtins first, in the prompt-specified cycle order — note this is
    // intentionally *not* `BUILTIN_AGENT_NAMES` order (which interleaves the
    // subagents) nor the settings toggle's order.
    let mut out: Vec<String> = ["Auto", "Plan", "Build", "Swarm"]
        .into_iter()
        .filter(|name| !is_hidden_primary(name))
        .filter(|name| experimental || !is_experimental_primary(name))
        .map(str::to_string)
        .collect();

    // User-defined chat-ownable agents, alphabetical by name. `list_all`
    // already de-dupes and folds built-in overrides into the built-in entry,
    // so a custom name here is genuinely non-builtin.
    let mut custom: Vec<String> = list_all(cwd)
        .into_iter()
        .filter(|listing| matches!(listing.kind, AgentKind::Custom))
        .filter_map(|listing| match listing.def {
            Ok(def) if def.mode.is_chat_ownable() => Some(listing.name),
            _ => None,
        })
        .collect();
    custom.sort();
    out.extend(custom);
    out
}

/// The next primary agent in the wrapping cycle, given the currently active
/// agent `current` and the ordered cycle list `order` (as built by
/// [`chat_ownable_primaries`]). Pure so the cycle order is unit-testable
/// without an `App`. When `current` is not in `order` (e.g. the chat is on a
/// subagent, or the active name is stale) the cycle starts at the front.
/// An empty `order` returns `current` unchanged (no-op).
pub fn next_primary_in_cycle(current: &str, order: &[String]) -> String {
    if order.is_empty() {
        return current.to_string();
    }
    match order.iter().position(|n| n == current) {
        Some(idx) => order[(idx + 1) % order.len()].clone(),
        None => order[0].clone(),
    }
}

impl AgentDef {
    /// The agent's effective system prompt for the active `llm_mode`
    /// (implementation note). For a directory-form agent
    /// this is the body of `<name>/<mode>.md`; when that mode's file was
    /// absent we fall back to the flat body in [`Self::prompt`] — except
    /// `frontier`, which first tries `normal.md` when present. A flat-file or
    /// embedded agent has no variants, so this is always [`Self::prompt`].
    /// Resolution funnels here rather than reading `self.prompt` at scattered
    /// sites.
    pub fn resolved_prompt_for(&self, mode: crate::config::extended::LlmMode) -> &str {
        use crate::config::extended::LlmMode;
        self.prompt_variants
            .get(&mode)
            .or_else(|| {
                (mode == LlmMode::Frontier)
                    .then(|| self.prompt_variants.get(&LlmMode::Normal))
                    .flatten()
            })
            .map(String::as_str)
            .unwrap_or(&self.prompt)
    }

    /// Serialize back to the on-disk `<name>.md` form: YAML frontmatter
    /// fence + the markdown body. Used by eject so a built-in's default
    /// materializes as a faithful, re-editable file.
    pub fn to_markdown(&self) -> Result<String> {
        // Build an ordered frontmatter map so the emitted file is stable
        // and human-friendly (description, mode, model, temperature,
        // tools, permission — only the fields that carry a value).
        let mut fm = serde_yaml::Mapping::new();
        fm.insert("description".into(), self.description.clone().into());
        fm.insert(
            "mode".into(),
            serde_yaml::to_value(self.mode)?
                .as_str()
                .unwrap_or("all")
                .into(),
        );
        if let Some(model) = &self.model {
            fm.insert("model".into(), model.clone().into());
        }
        if let Some(temp) = self.temperature {
            fm.insert("temperature".into(), (temp as f64).into());
        }
        if let Some(tools) = &self.tools {
            let seq: Vec<serde_yaml::Value> = tools.iter().map(|t| t.clone().into()).collect();
            fm.insert("tools".into(), serde_yaml::Value::Sequence(seq));
        }
        if !self.tool_descriptions.is_empty() {
            fm.insert(
                "tool_descriptions".into(),
                serde_yaml::to_value(&self.tool_descriptions)?,
            );
        }
        if let Some(scan) = self.scan_tool_results {
            fm.insert("scanToolResults".into(), scan.into());
        }
        if let Some(perm) = &self.permission {
            fm.insert("permission".into(), serde_yaml::to_value(perm)?);
        }
        let yaml = serde_yaml::to_string(&serde_yaml::Value::Mapping(fm))?;
        let body = self.prompt.trim_end_matches('\n');
        Ok(format!("---\n{yaml}---\n\n{body}\n"))
    }
}

/// Split a `<frontmatter>\n---\n<body>` markdown document into the raw
/// YAML frontmatter and the body. A document with no leading `---` fence
/// has an empty frontmatter and the whole text as body. The opening
/// fence must be the very first line.
fn split_frontmatter(text: &str) -> (&str, &str) {
    let rest = match text.strip_prefix("---\n") {
        Some(r) => r,
        // Tolerate a leading BOM / CRLF opening fence.
        None => match text.strip_prefix("---\r\n") {
            Some(r) => r,
            None => return ("", text),
        },
    };
    // Scan for the closing fence: a line that is exactly `---`.
    let mut offset = 0usize;
    for line in rest.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed == "---" {
            let fm = &rest[..offset];
            let body = &rest[offset + line.len()..];
            return (fm, body);
        }
        offset += line.len();
    }
    // No closing fence — treat the whole remainder as frontmatter-less.
    ("", text)
}

/// Parse YAML frontmatter + markdown body into an [`AgentDef`]. `name`
/// is the resolved agent name (the file stem); `source` is the path the
/// text came from (used in diagnostics). A missing `description` or bad
/// YAML fails with the `source` path named so the user's mistake isn't
/// hidden.
pub fn parse_agent(text: &str, name: &str, source: PathBuf) -> Result<AgentDef> {
    let (fm_raw, body) = split_frontmatter(text);

    #[derive(Deserialize)]
    struct Frontmatter {
        description: String,
        #[serde(default)]
        mode: AgentMode,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        temperature: Option<f32>,
        #[serde(default)]
        tools: Option<Vec<String>>,
        #[serde(default)]
        tool_descriptions: std::collections::BTreeMap<String, ToolDescriptionSpec>,
        #[serde(rename = "scanToolResults", default)]
        scan_tool_results: Option<bool>,
        #[serde(default)]
        permission: Option<serde_json::Value>,
    }

    if fm_raw.trim().is_empty() {
        bail!(
            "agent `{name}` ({}) has no YAML frontmatter — a `description` field is required",
            source.display()
        );
    }
    let fm: Frontmatter = serde_yaml::from_str(fm_raw).map_err(|e| {
        anyhow::anyhow!(
            "agent `{name}` ({}) has invalid frontmatter: {e}",
            source.display()
        )
    })?;
    if fm.description.trim().is_empty() {
        bail!(
            "agent `{name}` ({}) is missing a non-empty `description`",
            source.display()
        );
    }

    Ok(AgentDef {
        name: name.to_string(),
        description: fm.description,
        mode: fm.mode,
        model: fm.model,
        temperature: fm.temperature,
        tools: fm.tools,
        tool_descriptions: fm.tool_descriptions,
        scan_tool_results: fm.scan_tool_results,
        permission: fm.permission,
        // Trim the blank line(s) the frontmatter fence leaves before the
        // body and any trailing newline, so the stored prompt matches the
        // embedded-default form (the composer re-adds a single newline).
        prompt: body.trim_start_matches('\n').trim_end().to_string(),
        prompt_variants: std::collections::HashMap::new(),
        source,
    })
}

pub fn default_scan_tool_results(name: &str, mode: AgentMode) -> bool {
    match name {
        "explore" | "scout" | "docs-answerer" => false,
        _ if mode.is_chat_ownable() => true,
        _ => true,
    }
}

/// Load a single agent file from an arbitrary path. The file does not
/// need to live in any particular directory. Used by `cockpit run
/// --agent-file …`. The agent name is the file stem.
pub fn load_from_file(path: &Path) -> Result<AgentDef> {
    let text = read_agent_markdown(path)?;
    let name = agent_name_from_path(path)
        .ok_or_else(|| anyhow::anyhow!("agent file {} has no usable file stem", path.display()))?;
    let def = parse_agent(&text, &name, path.to_path_buf())?;
    validate_invariants(&def)?;
    Ok(def)
}

/// Load an agent-shaped markdown file while supplying the resolved logical
/// name from an owning entity. Assistants use this for
/// `<assistant-home>/assistant.md`: the file shape and validation stay exactly
/// the same as agents, while the persisted assistant name remains the entity
/// identity instead of the literal `assistant.md` stem.
pub fn load_named_from_file(path: &Path, name: &str) -> Result<AgentDef> {
    let text = read_agent_markdown(path)?;
    let def = parse_agent(&text, name, path.to_path_buf())?;
    validate_invariants(&def)?;
    Ok(def)
}

/// Load a per-`llm_mode` directory-form agent
/// (implementation note): `<dir>/<name>/<mode>.md`,
/// one file per mode. Each mode file is a full agent markdown with
/// frontmatter and body. Frontmatter (description / mode / tools / model /
/// temperature) is read from whichever mode file resolves first in
/// canonical order — the per-mode split is for the **prompt body**, not the
/// grant; the invariant validation runs once on the resulting def. The
/// per-mode bodies land in [`AgentDef::prompt_variants`];
/// [`AgentDef::prompt`] is set to the flat `<dir>/<name>.md` sibling when one
/// exists (the "fall back to flat" source), else to a present mode body so a
/// partial directory still loads.
///
/// `dir` is the search directory, `name` the agent name; the directory
/// `<dir>/<name>/` must exist (caller checks).
fn load_from_dir(dir: &Path, name: &str) -> Result<AgentDef> {
    use crate::config::extended::LlmMode;
    let agent_dir = dir.join(name);

    // Read each mode file present. Canonical order: defensive then normal
    // then frontier — the default mode leads so the frontmatter source is
    // stable.
    let modes = [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier];
    let mut variants: std::collections::HashMap<LlmMode, String> = std::collections::HashMap::new();
    let mut frontmatter_def: Option<AgentDef> = None;
    for mode in modes {
        let mode_path = agent_dir.join(mode.prompt_file());
        if !mode_path.is_file() {
            continue;
        }
        let text = read_agent_markdown(&mode_path)?;
        let parsed = parse_agent(&text, name, mode_path.clone())?;
        variants.insert(mode, parsed.prompt.clone());
        if frontmatter_def.is_none() {
            frontmatter_def = Some(parsed);
        }
    }

    // The flat `<dir>/<name>.md` sibling — the fall-back body for any mode
    // whose file is absent from the directory.
    let flat_path = dir.join(format!("{name}.md"));
    let flat_def = if flat_path.is_file() {
        Some(load_from_file(&flat_path)?)
    } else {
        None
    };

    // A directory with no mode files at all and no flat sibling is an
    // empty/malformed agent: error naming it (the user created `<name>/`
    // but populated no resolvable prompt).
    let mut base = match (frontmatter_def, flat_def.clone()) {
        (Some(def), _) => def,
        (None, Some(def)) => def,
        (None, None) => bail!(
            "agent `{name}` ({}) has no `defensive.md`/`normal.md`/`frontier.md` and no flat `{name}.md` sibling",
            agent_dir.display()
        ),
    };

    base.source = agent_dir;
    base.prompt_variants = variants;
    // The mode-agnostic flat body: the flat sibling when present (the
    // explicit fall-back source), else the frontmatter file's own body.
    if let Some(flat) = flat_def {
        base.prompt = flat.prompt;
    }
    validate_invariants(&base)?;
    Ok(base)
}

fn read_agent_markdown(path: &Path) -> Result<String> {
    let len = std::fs::metadata(path)
        .map_err(|e| anyhow::anyhow!("statting agent file {}: {e}", path.display()))?
        .len();
    if len > MAX_MARKDOWN_BYTES {
        tracing::warn!(
            path = %path.display(),
            size = len,
            limit = MAX_MARKDOWN_BYTES,
            "skipping oversized agent markdown"
        );
        bail!(
            "agent file {} exceeds {} byte limit",
            path.display(),
            MAX_MARKDOWN_BYTES
        );
    }
    std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading agent file {}: {e}", path.display()))
}

/// Extract the agent name from a path. For the flat-file form that is the
/// file stem (`builder.md` → `builder`); the dir form (`builder/`) — reserved
/// for the future per-`llm_mode` layout — would resolve to the directory
/// name. Centralized so the dir form can be accepted later without
/// touching call sites.
fn agent_name_from_path(path: &Path) -> Option<String> {
    if path.is_dir() {
        return path.file_name().map(|s| s.to_string_lossy().into_owned());
    }
    path.file_stem().map(|s| s.to_string_lossy().into_owned())
}

/// The on-disk agents directory inside a discovered config dir.
fn agents_subdir(config_dir: &Path) -> PathBuf {
    config_dir.join("agents")
}

/// Every directory to search for on-disk agent files, in left-to-right
/// override precedence: the layered config dirs (home/global, machine-
/// local, then project ancestors — see [`crate::config::dirs`]) each
/// contribute their `agents/` subdir, followed by configured
/// `extended.agent_dirs`. Unlike skills scan dirs, these entries are
/// resolved relative to the config file that defined them, not the process
/// cwd and not through ancestor-walk. This makes a checked-in project config
/// mean the same thing from every launch directory.
pub fn agent_search_dirs(cwd: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = crate::config::dirs::discover_config_dirs(cwd)
        .into_iter()
        .map(|d| agents_subdir(&d.path))
        .collect();
    dirs.extend(configured_agent_dirs_for_paths(
        &crate::config::dirs::config_file_paths_for_load(cwd),
    ));
    dirs
}

fn configured_agent_dirs_for_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for path in paths {
        if !path.exists() {
            continue;
        }
        let Ok(doc) = crate::config::extended::ExtendedConfigDoc::load(path) else {
            continue;
        };
        let Some(value) = doc.raw_field("agent_dirs") else {
            continue;
        };
        let parsed = match serde_json::from_value::<Vec<PathBuf>>(value.clone()) {
            Ok(parsed) => parsed,
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    key = "agent_dirs",
                    %error,
                    "skipping malformed extended config field"
                );
                continue;
            }
        };
        dirs = parsed
            .into_iter()
            .filter_map(|dir| resolve_agent_dir_entry(path, &dir))
            .filter(|dir| !crate::config::trust::path_blocked_by_workspace_trust(dir))
            .collect();
    }
    dirs
}

fn resolve_agent_dir_entry(config_path: &Path, dir: &Path) -> Option<PathBuf> {
    let rendered = dir.to_string_lossy();
    let resolved = crate::envref::resolve(&rendered);
    if resolved.has_missing() || resolved.has_errors() {
        tracing::warn!(
            path = %config_path.display(),
            key = "agent_dirs",
            missing = ?resolved.missing,
            errors = ?resolved.errors,
            "skipping unresolved agent_dirs entry"
        );
        return None;
    }
    let path = PathBuf::from(resolved.value);
    if path.is_absolute() {
        Some(path)
    } else {
        config_path.parent().map(|parent| parent.join(path))
    }
}

/// Resolve the on-disk path an agent named `name` would resolve to in
/// `dir`, **without** requiring it to exist. The per-`llm_mode` directory
/// form (`<dir>/<name>/`, holding `normal.md`/`defensive.md`) takes
/// precedence when present — it is the richer multi-mode source and
/// internally falls back to the flat `<dir>/<name>.md` sibling for any
/// absent mode (implementation note). Otherwise the
/// flat-file form (`<dir>/<name>.md`, the form eject writes) is returned;
/// when neither exists the flat path is returned as the canonical default.
pub fn agent_path_in(dir: &Path, name: &str) -> PathBuf {
    // The per-mode directory form wins when it exists.
    let dir_form = dir.join(name);
    if dir_form.is_dir() {
        return dir_form;
    }
    dir.join(format!("{name}.md"))
}

/// Find the first existing on-disk override file for `name`, scanning
/// [`agent_search_dirs`] in precedence order. Returns the path (flat-file
/// or — once supported — the dir form) of the highest-precedence match,
/// or `None` when no override exists (the embedded default applies).
pub fn find_override(cwd: &Path, name: &str) -> Option<PathBuf> {
    for dir in agent_search_dirs(cwd) {
        let candidate = agent_path_in(&dir, name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Resolve the effective [`AgentDef`] for `name` at `cwd`: the highest-
/// precedence on-disk override if one exists, else the embedded default
/// (for a built-in name). Returns `Ok(None)` when `name` is neither a
/// built-in nor present on disk. A malformed override file fails loudly
/// (naming its `source`) rather than silently falling back to the
/// embedded default — that would hide the user's mistake.
pub fn resolve(cwd: &Path, name: &str) -> Result<Option<AgentDef>> {
    for dir in agent_search_dirs(cwd) {
        let candidate = agent_path_in(&dir, name);
        if candidate.is_dir() {
            // Per-`llm_mode` directory form: load every mode file present,
            // falling back to the flat sibling per mode.
            return Ok(Some(load_from_dir(&dir, name)?));
        }
        if candidate.is_file() {
            return Ok(Some(load_from_file(&candidate)?));
        }
    }
    if let Some(def) = embedded_default(name) {
        return Ok(Some(def));
    }
    resolve_assistant_agent(name)
}

fn resolve_assistant_agent(name: &str) -> Result<Option<AgentDef>> {
    let Ok(db) = crate::db::Db::open_default() else {
        return Ok(None);
    };
    let Some(row) = db.get_assistant(name)? else {
        return Ok(None);
    };
    Ok(Some(crate::assistants::load_from_row(&row)?.agent))
}

/// Discover every agent visible at `cwd`: each built-in (overridden when
/// an on-disk file exists), plus every custom agent found on disk.
/// Override-by-name means a custom file whose stem collides with a
/// built-in name is folded into that built-in's entry, not listed twice.
/// Malformed files are surfaced as `Err` entries paired with the name so
/// callers (the `/settings` page) can show the problem rather than drop
/// the agent silently.
pub fn list_all(cwd: &Path) -> Vec<AgentListing> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<AgentListing> = Vec::new();

    // Built-ins first, in their canonical order, so the list leads with
    // the bundled cast.
    for &name in BUILTIN_AGENT_NAMES {
        let overridden = find_override(cwd, name).is_some();
        let result = resolve(cwd, name).map(|o| o.expect("built-in always resolves"));
        out.push(AgentListing {
            name: name.to_string(),
            kind: AgentKind::Builtin { overridden },
            def: result,
        });
        seen.insert(name.to_string());
    }

    // Then custom agents from disk, de-duplicated across the search path
    // (highest-precedence wins) and skipping built-in names (already
    // folded in above as overrides).
    for dir in agent_search_dirs(cwd) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = agent_file_candidate_name(&path) else {
                continue;
            };
            if seen.contains(&name) {
                continue;
            }
            if agent_markdown_oversized(&path, &dir, &name) {
                continue;
            }
            seen.insert(name.clone());
            let def = if path.is_dir() {
                load_from_dir(&dir, &name)
            } else {
                load_from_file(&path)
            };
            out.push(AgentListing {
                name,
                kind: AgentKind::Custom,
                def,
            });
        }
    }

    out
}

fn agent_markdown_oversized(path: &Path, dir: &Path, name: &str) -> bool {
    let paths: Vec<PathBuf> = if path.is_dir() {
        use crate::config::extended::LlmMode;
        [LlmMode::Defensive, LlmMode::Normal, LlmMode::Frontier]
            .into_iter()
            .map(|mode| path.join(mode.prompt_file()))
            .chain(std::iter::once(dir.join(format!("{name}.md"))))
            .filter(|p| p.is_file())
            .collect()
    } else {
        vec![path.to_path_buf()]
    };
    paths.into_iter().any(|p| match std::fs::metadata(&p) {
        Ok(meta) if meta.len() > MAX_MARKDOWN_BYTES => {
            tracing::warn!(
                path = %p.display(),
                size = meta.len(),
                limit = MAX_MARKDOWN_BYTES,
                "skipping oversized agent markdown"
            );
            true
        }
        _ => false,
    })
}

/// Return the candidate agent name for a dir entry: the stem of a `.md`
/// file, or a directory name (the reserved per-mode form). Non-`.md`
/// files are ignored.
fn agent_file_candidate_name(path: &Path) -> Option<String> {
    if path.is_dir() {
        return path.file_name().map(|s| s.to_string_lossy().into_owned());
    }
    if path.extension().and_then(|e| e.to_str()) == Some("md") {
        return path.file_stem().map(|s| s.to_string_lossy().into_owned());
    }
    None
}

/// One row in the agents listing: a built-in (possibly overridden) or a
/// custom agent, with its parsed definition or the parse error.
pub struct AgentListing {
    pub name: String,
    pub kind: AgentKind,
    pub def: Result<AgentDef>,
}

/// Whether a listed agent is one of the bundled cast or user-authored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentKind {
    /// A built-in agent. `overridden` is true when an on-disk file
    /// shadows its embedded default.
    Builtin { overridden: bool },
    /// A user-authored custom agent (any non-built-in name).
    Custom,
}

/// Eject a built-in agent's embedded default to `<config_dir>/agents/
/// <name>.md` for editing. If an override already exists anywhere on the
/// search path, **do not clobber** it — return its existing path so the
/// caller can open/select it instead. Returns `(path, newly_written)`.
pub fn eject_builtin(cwd: &Path, config_dir: &Path, name: &str) -> Result<(PathBuf, bool)> {
    if !is_builtin_agent(name) {
        bail!("`{name}` is not a built-in agent and cannot be ejected");
    }
    if let Some(existing) = find_override(cwd, name) {
        return Ok((existing, false));
    }
    let def = embedded_default(name).expect("built-in always has an embedded default");
    let dir = agents_subdir(config_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| anyhow::anyhow!("creating agents dir {}: {e}", dir.display()))?;
    let path = dir.join(format!("{name}.md"));
    let md = def.to_markdown()?;
    std::fs::write(&path, md)
        .map_err(|e| anyhow::anyhow!("writing agent file {}: {e}", path.display()))?;
    Ok((path, true))
}

/// Reset all built-in agent overrides: delete every on-disk override
/// file for a **built-in** name across the whole search path, restoring
/// the embedded defaults. Custom agents (non-built-in names) are never
/// touched. With no overrides present this is a safe no-op. Returns the
/// paths that were removed.
pub fn reset_all_builtins(cwd: &Path) -> Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    for dir in agent_search_dirs(cwd) {
        for &name in BUILTIN_AGENT_NAMES {
            let flat = dir.join(format!("{name}.md"));
            if flat.is_file() {
                std::fs::remove_file(&flat)
                    .map_err(|e| anyhow::anyhow!("removing {}: {e}", flat.display()))?;
                removed.push(flat);
            }
            // Reserved per-mode dir form — remove it too so a reset is
            // complete once that form ships.
            let dir_form = dir.join(name);
            if dir_form.is_dir() {
                std::fs::remove_dir_all(&dir_form)
                    .map_err(|e| anyhow::anyhow!("removing {}: {e}", dir_form.display()))?;
                removed.push(dir_form);
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests;
