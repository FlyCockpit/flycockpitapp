//! Embedded default [`AgentDef`]s for the bundled cast.
//!
//! The agent prompt bodies live as `include_str!`-baked markdown in
//! [`crate::engine::builtin`]; this module wraps each with the
//! frontmatter (description / mode / tool surface) that the hardcoded
//! factory functions encode in Rust. Together they are the fallback
//! definition for a built-in when no on-disk override exists — and the
//! faithful source eject writes to `<config_dir>/agents/<name>.md`.
//!
//! In scope: every bundled agent **except the docs pipeline**. The docs
//! resolver/answerer are a fixed two-stage pipeline (GOALS §3a), never an
//! [`AgentDef`], so they are absent here.
//!
//! `model`/`temperature` are left `None` on the defaults: a built-in
//! inherits the session's active model + params unless the user sets an
//! override in the ejected file. `tools` is the explicit role surface so
//! the engine can rebuild the toolbox from an edited grant.

use std::path::PathBuf;

use super::{AgentDef, AgentMode};

/// Names of the built-in agents in scope for user editing, in canonical
/// listing order. Drives the override-resolution, listing, and reset
/// paths. Driven off the code (the factory functions).
pub const BUILTIN_AGENT_NAMES: &[&str] = &[
    "Auto",
    "Build",
    "builder",
    "explore",
    "deepthink",
    "scout",
    "Plan",
    "Swarm",
    "bee",
    "Multireview",
];

/// True when `name` is one of the editable built-in agents.
pub fn is_builtin_agent(name: &str) -> bool {
    BUILTIN_AGENT_NAMES.contains(&name)
}

/// The builtin primaries gated behind experimental mode
/// (implementation note): `Auto`, `Plan`, and `Swarm`. The single source of truth for the gated-name set — every
/// gate decision (`chat_ownable_primaries` filtering, the front-door /
/// stale-session fallback in [`resolve_primary_for_flag`], the `/settings`
/// `defaultPrimaryAgent` cycle, the slash-swap rejection) derives from this
/// list, so the names are never duplicated across call sites.
pub const EXPERIMENTAL_PRIMARY_NAMES: &[&str] = &["Auto", "Plan", "Swarm"];

/// True when `name` is a builtin primary gated behind experimental mode.
/// `Build` (and every user-defined custom primary) is never gated. This is
/// the single predicate the rest of the gate routes through.
pub fn is_experimental_primary(name: &str) -> bool {
    EXPERIMENTAL_PRIMARY_NAMES.contains(&name)
}

/// Built-in primaries that are real primary agents but never appear in the
/// normal `/agent` list or Shift+Tab cycle. They are reached only through a
/// dedicated feature flow.
pub const HIDDEN_PRIMARY_NAMES: &[&str] = &["Multireview"];

pub fn is_hidden_primary(name: &str) -> bool {
    HIDDEN_PRIMARY_NAMES.contains(&name)
}

/// The non-experimental builtin primary the gate falls back to when
/// experimental mode is off (implementation note).
pub const FALLBACK_PRIMARY: &str = "Build";

/// Resolve a candidate primary-agent `name` against the experimental flag:
/// when `experimental_mode` is off and `name` is an
/// [`is_experimental_primary`] builtin, silently fall back to
/// [`FALLBACK_PRIMARY`] (`Build`); otherwise return `name` unchanged. Used
/// by the default front-door resolution and the stale-session resume path
/// so that, with experimental off, the active primary is never a gated
/// agent.
pub fn resolve_primary_for_flag(name: &str, experimental_mode: bool) -> String {
    if !experimental_mode && is_experimental_primary(name) {
        FALLBACK_PRIMARY.to_string()
    } else {
        name.to_string()
    }
}

/// The embedded default [`AgentDef`] for a built-in `name`, or `None`
/// when `name` is not a built-in. The `prompt` is the same body the
/// factory functions compose into the system prompt.
pub fn embedded_default(name: &str) -> Option<AgentDef> {
    match name {
        "Auto" => Some(auto_def()),
        "Build" => Some(build_def()),
        "builder" => Some(builder_def()),
        "explore" => Some(explore_def()),
        "deepthink" => Some(deepthink_def()),
        "scout" => Some(scout_def()),
        "Plan" => Some(plan_def()),
        "Swarm" => Some(swarm_def()),
        "bee" => Some(bee_def()),
        "Multireview" => Some(multireview_def()),
        _ => None,
    }
}

pub(crate) fn embedded_internal_default(name: &str) -> Option<AgentDef> {
    match name {
        "computer" => Some(computer_def()),
        "docs-resolver" => Some(docs_resolver_def()),
        "docs-answerer" => Some(docs_answerer_def()),
        _ => None,
    }
}

fn def(name: &str, description: &str, mode: AgentMode, tools: &[&str], prompt: &str) -> AgentDef {
    def_with_normal(name, description, mode, tools, prompt, None)
}

/// Build an embedded default carrying both LLM-mode prompt variants
/// (implementation note). `prompt` is the
/// flat `defensive` body — the default and the mode-agnostic flat fallback;
/// `normal` is the terser strong-model body. The defensive body is recorded
/// under both [`AgentDef::prompt`] (the flat fallback) and
/// `prompt_variants[Defensive]`, so [`AgentDef::resolved_prompt_for`] returns
/// the mode-appropriate body and still has a valid fallback when a variant is
/// absent. `normal: None` leaves the agent single-mode (the flat body serves
/// both modes via the fallback).
fn def_with_normal(
    name: &str,
    description: &str,
    mode: AgentMode,
    tools: &[&str],
    prompt: &str,
    normal: Option<&str>,
) -> AgentDef {
    use crate::config::extended::LlmMode;
    // Trim the trailing newline each `include_str!` body carries so an
    // embedded default and the same agent re-parsed from its ejected file
    // compare byte-equal (eject faithfulness).
    let defensive = prompt.trim_end().to_string();
    let mut prompt_variants = std::collections::HashMap::new();
    if let Some(n) = normal {
        prompt_variants.insert(LlmMode::Defensive, defensive.clone());
        prompt_variants.insert(LlmMode::Normal, n.trim_end().to_string());
    }
    AgentDef {
        name: name.to_string(),
        description: description.to_string(),
        mode,
        model: None,
        temperature: None,
        tools: Some(tools.iter().map(|t| t.to_string()).collect()),
        // Embedded defaults carry their per-agent tool wording in the
        // hardcoded factories ([`crate::engine::builtin`]), not here — the
        // generic markdown path uses this field only for user-authored agents.
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: Some(super::default_scan_tool_results(name, mode)),
        permission: None,
        prompt: defensive,
        prompt_variants,
        // Embedded defaults have no on-disk source.
        source: PathBuf::new(),
    }
}

/// `Auto` — the default front-door primary. Converses, answers plain
/// questions directly, and routes to `Plan`/`Build` via the `handoff`
/// tool. Tool surface mirrors [`crate::engine::builtin::auto`].
fn auto_def() -> AgentDef {
    def_with_normal(
        "Auto",
        "Default front-door agent; converses and hands off to `Plan` or `Build` once intent is clear.",
        AgentMode::Primary,
        &[
            "read", "bash", "search", "skill", "question", "handoff", "mcp",
        ],
        crate::engine::builtin::AUTO_PROMPT,
        Some(crate::engine::builtin::AUTO_PROMPT_NORMAL),
    )
}

/// `Build` — the user-facing, write-capable primary agent (GOALS §3a).
/// Delegate-eager: hands substantive work to `builder` via `task`, writes
/// inline only for small single-scope edits. Tool surface mirrors
/// [`crate::engine::builtin::build`].
fn build_def() -> AgentDef {
    def_with_normal(
        "Build",
        "Primary coding agent; write-capable but delegate-eager, hands feature work to `builder`.",
        AgentMode::Primary,
        &[
            "read",
            "bash",
            // full intel (GOALS §21)
            "context_pack",
            "tree",
            "outline",
            "symbol_find",
            "word",
            "deps",
            "hot",
            "circular",
            "search",
            "impact",
            "change_impact",
            // write/lock set (arbitrated by the lock authority)
            "readlock",
            "writeunlock",
            "editunlock",
            "unlock",
            "schedule",
            "question",
            "skill",
            "skill_manage",
            "harness_list",
            "harness_invoke",
            "task",
            "mcp",
        ],
        crate::engine::builtin::BUILD_PROMPT,
        Some(crate::engine::builtin::BUILD_PROMPT_NORMAL),
    )
}

/// `builder` — a write-capable worker subagent (holds file locks). Mirrors
/// `Build`'s write+intel surface minus general feature-delegation (keeps
/// `task→docs`, no `schedule`); do-it-yourself within scope. Tool surface mirrors
/// [`crate::engine::builtin::builder`].
fn builder_def() -> AgentDef {
    def_with_normal(
        "builder",
        "Write-capable worker; holds locks and applies edits, does its scope itself.",
        AgentMode::Subagent,
        &[
            "read",
            "readlock",
            "writeunlock",
            "unlock",
            "editunlock",
            "bash",
            // full intel (GOALS §21)
            "context_pack",
            "tree",
            "outline",
            "symbol_find",
            "word",
            "deps",
            "hot",
            "circular",
            "search",
            "impact",
            "change_impact",
            "question",
            "skill",
            "task",
            "mcp",
        ],
        crate::engine::builtin::BUILDER_PROMPT,
        Some(crate::engine::builtin::BUILDER_PROMPT_NORMAL),
    )
}

/// `explore` — read-only investigator, leaf in the invocation tree. Tool
/// surface mirrors [`crate::engine::builtin::explore`].
fn explore_def() -> AgentDef {
    def_with_normal(
        "explore",
        "Read-only investigator; finds where things live and reports back.",
        AgentMode::Subagent,
        &[
            "read",
            "bash",
            "context_pack",
            "tree",
            "outline",
            "symbol_find",
            "word",
            "deps",
            "hot",
            "circular",
            "search",
            "impact",
            "change_impact",
            "lsp",
        ],
        crate::engine::builtin::EXPLORE_PROMPT,
        Some(crate::engine::builtin::EXPLORE_PROMPT_NORMAL),
    )
}

/// `deepthink` — optional tool-free reasoning worker. It receives only its
/// standalone task prompt plus explicit seeds, then returns structured
/// analysis.
fn deepthink_def() -> AgentDef {
    def(
        "deepthink",
        "Optional tool-free reasoning worker; analyzes a brief and returns structured fields.",
        AgentMode::Subagent,
        &[],
        crate::engine::builtin::DEEPTHINK_PROMPT,
    )
}

/// `scout` — read-only recursive review worker. Mirrors `explore` plus
/// `spawn` and `return`; no write/lock tools.
fn scout_def() -> AgentDef {
    def_with_normal(
        "scout",
        "Read-only recursive review worker; reviews a scoped surface and may spawn deeper `scout` workers.",
        AgentMode::Subagent,
        &[
            "read",
            "bash",
            "context_pack",
            "tree",
            "outline",
            "symbol_find",
            "word",
            "deps",
            "hot",
            "circular",
            "search",
            "impact",
            "change_impact",
            "spawn",
            "return",
        ],
        crate::engine::builtin::SCOUT_PROMPT,
        Some(crate::engine::builtin::SCOUT_PROMPT_NORMAL),
    )
}

/// `Plan` — the user-facing read-only planning agent. It investigates,
/// maintains a virtual session plan document, and hands it to `Build`.
/// Tool surface mirrors [`crate::engine::builtin::plan`].
fn plan_def() -> AgentDef {
    def_with_normal(
        "Plan",
        "Read-only planning agent; maintains a virtual plan document and hands it to Build.",
        AgentMode::Primary,
        &[
            "read",
            "bash",
            // full intel (GOALS §21)
            "context_pack",
            "tree",
            "outline",
            "symbol_find",
            "word",
            "deps",
            "hot",
            "circular",
            "search",
            "impact",
            "change_impact",
            "lsp",
            "plan_read",
            "plan_write",
            "plan_edit",
            "start_build",
            "question",
            "skill",
            "harness_list",
            "harness_invoke",
            "task",
            "mcp",
        ],
        crate::engine::builtin::PLAN_PROMPT,
        Some(crate::engine::builtin::PLAN_PROMPT_NORMAL),
    )
}

/// `Swarm` — the interactive, write-capable recursive fan-out primary
/// (GOALS §24/§26). `Build`'s full surface plus the `spawn` tool for
/// recursive, parallel, background `bee` fan-out — the sole leaf-termination
/// exception. Tool surface mirrors [`crate::engine::builtin::swarm`].
fn swarm_def() -> AgentDef {
    def_with_normal(
        "Swarm",
        "Recursive fan-out primary; write-capable, partitions a wide task into parallel background `bee` workers.",
        AgentMode::Primary,
        &[
            "read",
            "bash",
            // full intel (GOALS §21)
            "context_pack",
            "tree",
            "outline",
            "symbol_find",
            "word",
            "deps",
            "hot",
            "circular",
            "search",
            "impact",
            "change_impact",
            // write/lock set (arbitrated by the lock authority)
            "readlock",
            "writeunlock",
            "editunlock",
            "unlock",
            "schedule",
            "question",
            "skill",
            "skill_manage",
            "harness_list",
            "harness_invoke",
            "task",
            "spawn",
            "mcp",
        ],
        crate::engine::builtin::SWARM_PROMPT,
        Some(crate::engine::builtin::SWARM_PROMPT_NORMAL),
    )
}

/// `bee` — `Swarm`'s recursive, noninteractive, write-capable worker
/// (GOALS §24/§26). `builder`'s write+intel surface plus `spawn` for deeper
/// fan-out; no base MCP (parent-grantable). Tool surface mirrors
/// [`crate::engine::builtin::bee`].
fn bee_def() -> AgentDef {
    def_with_normal(
        "bee",
        "Noninteractive parallel worker; write-capable, does its briefed slice and may fan out deeper `bee` workers.",
        AgentMode::Subagent,
        &[
            "read",
            "readlock",
            "writeunlock",
            "editunlock",
            "unlock",
            "bash",
            // full intel (GOALS §21)
            "context_pack",
            "tree",
            "outline",
            "symbol_find",
            "word",
            "deps",
            "hot",
            "circular",
            "search",
            "impact",
            "change_impact",
            "skill",
            "task",
            "spawn",
        ],
        crate::engine::builtin::BEE_PROMPT,
        Some(crate::engine::builtin::BEE_PROMPT_NORMAL),
    )
}

/// `Multireview` — hidden read-only primary reached only by `/multireview`.
fn multireview_def() -> AgentDef {
    def_with_normal(
        "Multireview",
        "Hidden read-only multi-model review orchestrator reached only through `/multireview`.",
        AgentMode::Primary,
        &[
            "read",
            "bash",
            "context_pack",
            "tree",
            "outline",
            "symbol_find",
            "word",
            "deps",
            "hot",
            "circular",
            "search",
            "impact",
            "change_impact",
            "spawn",
            "harness_list",
            "harness_invoke",
            "schedule",
            "question",
        ],
        crate::engine::builtin::MULTIREVIEW_PROMPT,
        Some(crate::engine::builtin::MULTIREVIEW_PROMPT_NORMAL),
    )
}

fn computer_def() -> AgentDef {
    def(
        "computer",
        "Internal provider-native computer-use worker.",
        AgentMode::Subagent,
        &["return"],
        crate::engine::builtin::COMPUTER_PROMPT,
    )
}

fn docs_resolver_def() -> AgentDef {
    def(
        "docs-resolver",
        "Internal docs pipeline resolver stage.",
        AgentMode::Subagent,
        &["bash"],
        crate::engine::builtin::DOCS_RESOLVER_PROMPT,
    )
}

fn docs_answerer_def() -> AgentDef {
    def(
        "docs-answerer",
        "Internal docs pipeline answerer stage.",
        AgentMode::Subagent,
        &["read", "grep", "glob"],
        crate::engine::builtin::DOCS_ANSWERER_PROMPT,
    )
}
