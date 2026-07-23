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

use super::{AgentDef, AgentMode, ToolDescriptionSpec, ToolTier};

/// Names of the built-in agents in scope for user editing, in canonical
/// listing order. Drives the override-resolution, listing, and reset
/// paths. Driven off the code (the factory functions).
pub const BUILTIN_AGENT_NAMES: &[&str] = &[
    "Build",
    "builder",
    "explore",
    "deepthink",
    "scout",
    "Plan",
    "bee",
    "Multireview",
];

/// True when `name` is one of the editable built-in agents.
pub fn is_builtin_agent(name: &str) -> bool {
    BUILTIN_AGENT_NAMES.contains(&name)
}

/// Builtin primaries removed before release. These names stay reserved so
/// stale sessions/configs degrade to `Build` and old ejected overrides do not
/// resurrect them as custom agents.
pub const REMOVED_PRIMARY_NAMES: &[&str] = &["Auto", "Swarm"];

pub fn is_removed_primary(name: &str) -> bool {
    REMOVED_PRIMARY_NAMES.contains(&name)
}

/// Built-in primaries that are real primary agents but never appear in the
/// normal `/agent` list or Shift+Tab cycle. They are reached only through a
/// dedicated feature flow.
pub const HIDDEN_PRIMARY_NAMES: &[&str] = &["Multireview"];

pub fn is_hidden_primary(name: &str) -> bool {
    HIDDEN_PRIMARY_NAMES.contains(&name)
}

/// The builtin primary used when a stored or configured primary is no longer
/// available.
pub const FALLBACK_PRIMARY: &str = "Build";

/// The embedded default [`AgentDef`] for a built-in `name`, or `None`
/// when `name` is not a built-in. The `prompt` is the same body the
/// factory functions compose into the system prompt.
pub fn embedded_default(name: &str) -> Option<AgentDef> {
    match name {
        "Build" => Some(build_def()),
        "builder" => Some(builder_def()),
        "explore" => Some(explore_def()),
        "deepthink" => Some(deepthink_def()),
        "scout" => Some(scout_def()),
        "Plan" => Some(plan_def()),
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
        tool_tiers: std::collections::BTreeMap::<String, ToolTier>::new(),
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: Some(super::default_scan_tool_results(name, mode)),
        permission: None,
        prompt: defensive,
        prompt_variants,
        // Embedded defaults have no on-disk source.
        source: PathBuf::new(),
    }
}

/// `Build` — the user-facing, write-capable primary agent (GOALS §3a).
/// Delegate-eager: hands substantive work to `builder` via `task`, writes
/// inline only for small single-scope edits. Tool surface mirrors
/// [`crate::engine::builtin::build`].
fn build_def() -> AgentDef {
    let mut def = def_with_normal(
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
            "lsp",
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
    );
    def.tool_descriptions.insert(
        "task".to_string(),
        ToolDescriptionSpec::PerMode {
            normal: Some(
                "Delegate substantive feature work to a subagent (builder writes, explore investigates); if task returns backgrounded JSON, the call is closed but the child is detached/result-pending, so use task_call_id controls or the async result rather than duplicate work; use docs by default for unfamiliar or version-sensitive dependency APIs"
                    .to_string(),
            ),
            frontier: Some(
                "Write small local edits directly; delegate larger, multi-file, risky, or isolated work to builder/explore; backgrounded JSON means the task call closed but the child is detached/result-pending; use docs when APIs are unfamiliar or version-sensitive"
                    .to_string(),
            ),
            defensive: Some(
                "Delegate substantive implementation instead of doing it inline: hand each \
                 well-scoped piece to `builder` to write/edit files, or to `explore` for \
                 read-only investigation, with a complete standalone brief (goal, constraints, \
                 exact files, what \"done\" looks like). Each `builder` task is one \
                 implementation slice, not a bundle of unrelated asks. If the user asks for a \
                 follow-up implementation iteration after `builder` returns, start a fresh \
                 `builder` brief seeded with the prior result summary, relevant changed files, \
                 and the new request. For how to USE a third-party dependency's API, your first \
                 move is `docs` (JSON `{package, question}`), including dependency questions \
                 found while preparing a `builder` brief; skip it only when exact usage is \
                 clearly established in already-read local code. If a task returns a backgrounded \
                 task_delegation JSON envelope, the tool call is closed but the child is detached \
                 with result_pending=true; do not treat it as the report or redelegate solely \
                 because it backgrounded. Continue the conversation and act on the async result, \
                 or poll status/query/list by task_call_id. Read each child status/error; steer \
                 only applies at the next child turn boundary if still running/actionable. Your \
                 own inline work is limited to orchestration and short read-only lookups."
                    .to_string(),
            ),
        },
    );
    def
}

/// `builder` — a write-capable worker subagent (holds file locks). Mirrors
/// `Build`'s write+intel surface minus general feature-delegation (keeps
/// `task→docs`, no `schedule`); do-it-yourself within scope. Tool surface mirrors
/// [`crate::engine::builtin::builder`].
fn builder_def() -> AgentDef {
    let mut def = def_with_normal(
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
            "lsp",
            "question",
            "skill",
            "task",
            "mcp",
            "defer_to_orchestrator",
        ],
        crate::engine::builtin::BUILDER_PROMPT,
        Some(crate::engine::builtin::BUILDER_PROMPT_NORMAL),
    );
    def.tool_descriptions.insert(
        "task".to_string(),
        ToolDescriptionSpec::PerMode {
            normal: Some(
                "Use `task` only for docs by default for unfamiliar APIs; if docs backgrounds, the call is closed but detached/result-pending, so use the async result or task_call_id controls rather than guess or retry; otherwise do the assigned code work yourself"
                    .to_string(),
            ),
            frontier: Some(
                "Use `task` only for docs when APIs are unfamiliar; if docs backgrounds, the call is closed but detached/result-pending, so use the async result or task_call_id controls rather than guess or retry; otherwise do the assigned code work yourself"
                    .to_string(),
            ),
            defensive: Some(
                "Do the assigned code work yourself — read, lock, edit, and verify in this context. \
                 Use `task` only to ask the `docs` pipeline how a third-party dependency's API \
                 works — and when you need that API, asking `docs` is your first move, not a guess \
                 or a web search, unless the exact usage pattern is clearly established in \
                 already-read local code: a source-cited answer is worth the tokens. Do exactly \
                 one assigned implementation slice. Do not try to delegate the feature itself or \
                 accept new feature work outside the brief. If the request turns out to be out of \
                 your assigned scope, return the out-of-scope ask to your caller via the structured \
                 `return` report rather than expanding it. If a docs task returns backgrounded \
                 task_delegation JSON, the call is closed but detached/result-pending; wait for \
                 the async result or query/list/status by task_call_id, and read child status/error \
                 because docs can fail, be cancelled, or be lost."
                    .to_string(),
            ),
        },
    );
    def
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
            "defer_to_orchestrator",
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
            "lsp",
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

/// `bee` — recursive, noninteractive, write-capable fan-out worker
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
            "lsp",
            "skill",
            "task",
            "spawn",
        ],
        crate::engine::builtin::BEE_PROMPT,
        Some(crate::engine::builtin::BEE_PROMPT_NORMAL),
    )
}

/// `Multireview` — hidden read-only primary reached only by `/multireview`.
/// Grants `mcp` so its discoverable harness tools are reachable through the
/// MCP harness advert named by the role prompt.
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
            "lsp",
            "spawn",
            "harness_list",
            "harness_invoke",
            "schedule",
            "question",
            "mcp",
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
    let mut def = def(
        "docs-answerer",
        "Internal docs pipeline answerer stage.",
        AgentMode::Subagent,
        &["read", "grep", "glob"],
        crate::engine::builtin::DOCS_ANSWERER_PROMPT,
    );
    def.tool_descriptions.insert(
        "grep".to_string(),
        ToolDescriptionSpec::PerMode {
            normal: Some(
                "Search file contents in this dependency package for a regex; with no shell here, use it to locate code before reading matches."
                    .to_string(),
            ),
            frontier: None,
            defensive: None,
        },
    );
    def.tool_descriptions.insert(
        "glob".to_string(),
        ToolDescriptionSpec::PerMode {
            normal: Some(
                "List files in this dependency package matching a glob; with no shell here, use it to discover entry points before reading them."
                    .to_string(),
            ),
            frontier: None,
            defensive: None,
        },
    );
    def
}
