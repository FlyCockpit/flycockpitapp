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

use super::{
    AgentDef, AgentMode, AllowedChild, DelegationPolicy, DelegationTarget, ExecutionKind,
    ModelCapability, ModelLocality, ModelSlot, ToolDescriptionSpec, ToolTier, VnextAgentDef,
};

/// Names of the built-in agents in scope for user editing, in canonical
/// listing order. Drives the override-resolution, listing, and reset
/// paths. Driven off the code (the factory functions).
pub const BUILTIN_AGENT_NAMES: &[&str] = &[
    "Build",
    "Careful",
    "builder",
    "explore",
    "history",
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

/// Public built-in primaries in the `/agent` listing and Shift+Tab cycle.
pub const PUBLIC_PRIMARY_NAMES: &[&str] = &["Plan", "Build", "Careful"];

/// Every built-in primary that may own a root session, including hidden
/// feature-flow primaries.
pub const BUILTIN_PRIMARY_NAMES: &[&str] = &["Plan", "Build", "Careful", "Multireview"];

pub fn is_builtin_primary(name: &str) -> bool {
    BUILTIN_PRIMARY_NAMES.contains(&name)
}

/// The builtin primary used when a stored or configured primary is no longer
/// available.
pub const FALLBACK_PRIMARY: &str = "Build";

/// Resolve the primary agent for a session (issue #75): the mode axis no
/// longer selects `Careful` automatically — `defaultPrimaryAgent` (the
/// configured default) governs. A stored/requested name wins (with
/// removed-primary fallback to `Build`); otherwise the configured default
/// applies (with the same removed-primary fallback).
pub fn resolve_primary(requested_or_stored: Option<&str>, configured_default: &str) -> String {
    match requested_or_stored.filter(|name| !name.is_empty()) {
        Some(name) if is_removed_primary(name) => FALLBACK_PRIMARY.to_string(),
        Some(name) => name.to_string(),
        None if is_removed_primary(configured_default) => FALLBACK_PRIMARY.to_string(),
        None => configured_default.to_string(),
    }
}

/// The embedded default [`AgentDef`] for a built-in `name`, or `None`
/// when `name` is not a built-in. The `prompt` is the same body the
/// factory functions compose into the system prompt.
pub fn embedded_default(name: &str) -> Option<AgentDef> {
    match name {
        "Build" => Some(build_def()),
        "Careful" => Some(careful_def()),
        "builder" => Some(builder_def()),
        "explore" => Some(explore_def()),
        "history" => Some(history_def()),
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
        "standard" => Some(standard_def()),
        _ => None,
    }
}

/// The universal fallback agent def (issue #75, decision 6): conservative
/// grants — none of the four capabilities, terse steering, default context
/// policy (80% auto-compact, standard inline caps). Used for cold start and
/// delegation to an undescribed model, always subject to no-widening
/// intersection against the parent's grants.
fn standard_def() -> AgentDef {
    def_with_normal(
        "standard",
        "Universal fallback agent — conservative grants, terse steering.",
        super::AgentMode::All,
        &[
            "read", "code", "search", "graph", "bash", "task", "question",
        ],
        "You are a general-purpose coding agent. Read and investigate before acting; delegate substantive work via `task`; report concise progress.",
        None,
    )
}

fn def(name: &str, description: &str, mode: AgentMode, tools: &[&str], prompt: &str) -> AgentDef {
    def_with_normal(name, description, mode, tools, prompt, None)
}

/// Build an embedded default. `prompt` is the single canonical body (issue
/// #75: the former per-mode defensive/normal/frontier body trios are merged
/// into one). The `normal` parameter is retained for call-site compatibility
/// but is now ignored — the merged `.md` file already carries the canonical
/// body. Per-model overrides are empty for embedded defaults.
fn def_with_normal(
    name: &str,
    description: &str,
    mode: AgentMode,
    tools: &[&str],
    prompt: &str,
    _normal: Option<&str>,
) -> AgentDef {
    // Trim the trailing newline each `include_str!` body carries so an
    // embedded default and the same agent re-parsed from its ejected file
    // compare byte-equal (eject faithfulness).
    let body = prompt.trim_end().to_string();
    let vnext = if matches!(name, "docs-resolver" | "docs-answerer") {
        // The docs pipeline is an internal two-stage implementation, not a
        // user-authored AgentDef language. Keep its fixed surfaces outside
        // vNext discovery and serialization.
        None
    } else {
        Some(builtin_vnext(name, mode))
    };
    let mut def = AgentDef {
        name: name.to_string(),
        description: description.to_string(),
        mode,
        model: None,
        temperature: None,
        tools: Some(tools.iter().map(|t| t.to_string()).collect()),
        tool_tiers: std::collections::BTreeMap::<String, ToolTier>::new(),
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: Some(super::default_scan_tool_results(name)),
        goal_supervision: super::GoalSettingsOverride::default(),
        permission: None,
        capabilities: None,
        tool_steering: None,
        context_policy: None,
        vnext,
        prompt: body,
        prompt_overrides: std::collections::BTreeMap::new(),
        package_files: None,
        private_subagents: std::collections::BTreeMap::new(),
        // Embedded defaults have no on-disk source.
        source: PathBuf::new(),
    };
    stamp_builtin_posture(&mut def, name);
    def
}

/// Stamp an embedded built-in def with its explicit issue-#75 posture:
/// capabilities, tool steering, and context policy. This makes agent
/// definitions the sole policy artifact — no code path resolves posture from
/// the session-global steering mode for shipped defs.
///
/// - `Careful` (the shipped single-model-defensive preset): verbose steering,
///   60% auto-compact floor, conservative inline caps, no extra capabilities.
/// - `Build`/`builder`: terse, defaults, `{followupSeed, sandboxEscalate,
///   forkContext, scopedParallelWrite}`.
/// - `bee`/`plan`/`explore`/`scout`/`history`/`multireview`/`deepthink`:
///   terse, defaults, `{followupSeed, sandboxEscalate}`.
/// - `computer`/docs agents: terse, defaults, no extra capabilities (`{}`).
fn stamp_builtin_posture(def: &mut AgentDef, name: &str) {
    use super::{AgentCapability, ContextPolicy, InlineCapsProfile, ToolSteering};
    let mut caps = std::collections::BTreeSet::new();
    match name {
        "Careful" => {
            def.tool_steering = Some(ToolSteering::Verbose);
            def.context_policy = Some(ContextPolicy {
                auto_compact_pct: Some(60),
                inline_caps: Some(InlineCapsProfile::Conservative),
            });
            // No extra capabilities — the conservative preset.
        }
        "Build" | "builder" => {
            def.tool_steering = Some(ToolSteering::Terse);
            caps.insert(AgentCapability::FollowupSeed);
            caps.insert(AgentCapability::SandboxEscalate);
            caps.insert(AgentCapability::ForkContext);
            caps.insert(AgentCapability::ScopedParallelWrite);
        }
        "bee" | "Plan" | "explore" | "scout" | "history" | "Multireview" | "deepthink" => {
            def.tool_steering = Some(ToolSteering::Terse);
            caps.insert(AgentCapability::FollowupSeed);
            caps.insert(AgentCapability::SandboxEscalate);
        }
        // computer / docs-resolver / docs-answerer / custom: no extra caps.
        _ => {
            def.tool_steering = Some(ToolSteering::Terse);
        }
    }
    def.capabilities = Some(caps);
}

/// Bundled definitions are authored by the binary, not by an editable
/// frontmatter file. Their historic tool arrays remain host-owned factory
/// inputs, while their ejected form is the closed v2 contract below.
fn builtin_vnext(name: &str, mode: AgentMode) -> VnextAgentDef {
    let execution_kind = if name == "computer" {
        ExecutionKind::Computer
    } else if mode.is_chat_ownable() {
        ExecutionKind::Assistant
    } else {
        ExecutionKind::Coding
    };
    // These are binary-owned reachability declarations mirroring the current
    // built-in task surfaces. They are serializable policy requests, never a
    // tool grant: the daemon still intersects them with its host policy and
    // resolves the portable ids uniquely before launch.
    let children: &[&str] = match name {
        "Build" | "Careful" => &["builder", "explore", "history", "deepthink", "scout"],
        "Plan" => &["explore", "history"],
        "Multireview" => &["scout"],
        "builder" | "bee" => &["explore"],
        _ => &[],
    };
    let delegation = if children.is_empty() {
        DelegationPolicy::default()
    } else {
        DelegationPolicy {
            allowed_children: children
                .iter()
                .map(|child| AllowedChild::PortableRef {
                    portable_agent_ref: format!("cockpit/{child}"),
                })
                .collect(),
            max_descendant_depth: Some(1),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
        }
    };
    VnextAgentDef {
        schema_version: super::SCHEMA_VERSION,
        agent_id: format!("cockpit/{}", name.to_ascii_lowercase()),
        execution_kind,
        model_slots: std::collections::BTreeMap::from([(
            "primary".to_string(),
            ModelSlot {
                purpose: "Primary model for this built-in role.".to_string(),
                min_context_tokens: 1,
                required_capabilities: vec![ModelCapability::TextGeneration],
                locality: ModelLocality::Any,
                allow_default_fallback: true,
                suggested_models: Vec::new(),
            },
        )]),
        delegation,
        questions: None,
        verification: None,
    }
}

/// `Careful` — the verbose/conservative write-capable primary. It keeps only
/// the minimum direct Build tools needed for ordinary edits; broader code intel,
/// skill, harness, and recall capabilities stay reachable through `mcp`.
fn careful_def() -> AgentDef {
    def(
        "Careful",
        "Conservative coding primary; small direct tool surface, uses `mcp` for broader Build capabilities.",
        AgentMode::Primary,
        &[
            "read",
            "bash",
            "search",
            "write",
            "edit",
            "unlock",
            "schedule",
            "question",
            "task",
            "mcp",
            "context_pack",
            "code",
            "graph",
            "change_impact",
            "lsp",
            "skill",
            "harness_list",
            "harness_invoke",
            "session_search",
            "session_read",
            "session_lineage_search",
            "todo",
            "webfetch",
            "websearch",
        ],
        crate::engine::builtin::CAREFUL_PROMPT,
    )
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
            "code",
            "graph",
            "search",
            "change_impact",
            "lsp",
            // write/lock set (arbitrated by the lock authority)
            "write",
            "edit",
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
        None,
    );
    def.tool_descriptions.insert(
        "task".to_string(),
        ToolDescriptionSpec::WithVerbose {
            text:
                "Delegate substantive feature work to a subagent (builder writes, explore investigates); handoff prompts may use @file, @file:XX-YY, @dir/, and /skill tags; if task returns backgrounded JSON, the call is closed but the child is detached/result-pending, so use task_call_id controls or the async result rather than duplicate work; use docs by default for unfamiliar or version-sensitive dependency APIs"
                    .to_string(),
            verbose_text: Some(
                "Delegate substantive implementation instead of doing it inline: hand each \
                 well-scoped piece to `builder` to write/edit files, or to `explore` for \
                 read-only investigation, with a complete standalone brief (goal, constraints, \
                 exact files, what \"done\" looks like). Use @file, @file:XX-YY, @dir/, and \
                 /skill tags in handoff prompts when the child needs source or skill context. \
                 Each `builder` task is one \
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
            "write",
            "unlock",
            "edit",
            "bash",
            // full intel (GOALS §21)
            "context_pack",
            "code",
            "graph",
            "search",
            "change_impact",
            "lsp",
            "question",
            "skill",
            "task",
            "mcp",
            "defer_to_orchestrator",
        ],
        crate::engine::builtin::BUILDER_PROMPT,
        None,
    );
    def.tool_descriptions.insert(
        "task".to_string(),
        ToolDescriptionSpec::WithVerbose {
            text:
                "Use `task` only for docs by default for unfamiliar APIs; if docs backgrounds, the call is closed but detached/result-pending, so use the async result or task_call_id controls rather than guess or retry; otherwise do the assigned code work yourself"
                    .to_string(),
            verbose_text: Some(
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
            "code",
            "graph",
            "search",
            "change_impact",
            "lsp",
            "defer_to_orchestrator",
        ],
        crate::engine::builtin::EXPLORE_PROMPT,
        None,
    )
}

/// `history` — read-only recall worker, leaf in the invocation tree. It uses
/// trust-filtered history tools in its own context and returns a short report.
fn history_def() -> AgentDef {
    let mut def = def_with_normal(
        "history",
        "Read-only recall worker; searches prior sessions and compaction lineage, then reports relevant excerpts.",
        AgentMode::Subagent,
        &[
            "read",
            "session_search",
            "session_read",
            "session_lineage_search",
        ],
        crate::engine::builtin::HISTORY_PROMPT,
        None,
    );
    for tool in ["session_search", "session_read", "session_lineage_search"] {
        def.tool_tiers.insert(tool.to_string(), ToolTier::Enabled);
    }
    def
}

/// `deepthink` — optional tool-free reasoning worker. It receives only its
/// standalone task prompt, then returns structured analysis.
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
            "code",
            "graph",
            "search",
            "change_impact",
            "lsp",
            "spawn",
            "return",
        ],
        crate::engine::builtin::SCOUT_PROMPT,
        None,
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
            "code",
            "graph",
            "search",
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
        None,
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
            "write",
            "edit",
            "unlock",
            "bash",
            // full intel (GOALS §21)
            "context_pack",
            "code",
            "graph",
            "search",
            "change_impact",
            "lsp",
            "skill",
            "task",
            "spawn",
        ],
        crate::engine::builtin::BEE_PROMPT,
        None,
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
            "code",
            "graph",
            "search",
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
        None,
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
        ToolDescriptionSpec::Text(
            "Search file contents in this dependency package for a regex; with no shell here, use it to locate code before reading matches."
                .to_string(),
        ),
    );
    def.tool_descriptions.insert(
        "glob".to_string(),
        ToolDescriptionSpec::Text(
            "List files in this dependency package matching a glob; with no shell here, use it to discover entry points before reading them."
                .to_string(),
        ),
    );
    def
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{AgentCapability, PostureResolution};

    fn effective_tier(def: &AgentDef, tool: &str) -> ToolTier {
        if crate::engine::builtin::default_disabled_tools_for(&def.name).contains(&tool) {
            return ToolTier::Disabled;
        }
        def.tool_tiers.get(tool).copied().unwrap_or_else(|| {
            if crate::engine::builtin::default_discoverable_tools_for(&def.name).contains(&tool) {
                ToolTier::Discoverable
            } else {
                ToolTier::Enabled
            }
        })
    }

    fn builtin_tool_names(def: &AgentDef) -> std::collections::BTreeSet<String> {
        def.tools
            .as_ref()
            .expect("embedded def has explicit tools")
            .iter()
            .filter(|tool| effective_tier(def, tool) == ToolTier::Enabled)
            .cloned()
            .collect()
    }

    fn effective_surface_names(def: &AgentDef) -> std::collections::BTreeSet<String> {
        def.tools
            .as_ref()
            .expect("embedded def has explicit tools")
            .iter()
            .filter(|tool| effective_tier(def, tool) != ToolTier::Disabled)
            .cloned()
            .collect()
    }

    #[test]
    fn configured_default_governs_primary_selection() {
        // Issue #75: the mode axis no longer selects Careful; the configured
        // default (`FALLBACK_PRIMARY` here) governs for brand-new sessions.
        assert_eq!(resolve_primary(None, FALLBACK_PRIMARY), FALLBACK_PRIMARY);
        assert_eq!(
            embedded_default("Careful")
                .expect("defensive primary embedded default")
                .name,
            "Careful"
        );
    }

    #[test]
    fn builtin_agents_grant_fork_context_only_where_intended() {
        for name in BUILTIN_AGENT_NAMES {
            let def = embedded_default(name).expect("builtin agent definition");
            let grants_fork_context = PostureResolution::from_def(&def)
                .grants()
                .contains(&AgentCapability::ForkContext);
            assert_eq!(
                grants_fork_context,
                matches!(*name, "Build" | "builder"),
                "unexpected forkContext grant for {name}"
            );
        }
    }

    #[test]
    fn configured_default_resolves_to_build_when_default_is_build() {
        let build = embedded_default(FALLBACK_PRIMARY).expect("Build embedded default");
        let resolved = resolve_primary(None, FALLBACK_PRIMARY);
        let resolved_def = embedded_default(&resolved).expect("resolved embedded default");

        assert_eq!(resolved, FALLBACK_PRIMARY);
        assert_eq!(resolved_def.tools, build.tools);
    }

    #[test]
    fn explicit_agent_choice_wins_over_default() {
        assert_eq!(resolve_primary(Some("Plan"), FALLBACK_PRIMARY), "Plan");
        assert_eq!(resolve_primary(Some("Build"), FALLBACK_PRIMARY), "Build");
        assert_eq!(
            resolve_primary(Some("custom-primary"), FALLBACK_PRIMARY),
            "custom-primary"
        );
    }

    #[test]
    fn removed_primary_falls_back_to_build() {
        assert_eq!(
            resolve_primary(Some("Swarm"), FALLBACK_PRIMARY),
            FALLBACK_PRIMARY,
            "removed stored primaries keep the existing Build fallback"
        );
        assert_eq!(
            resolve_primary(None, "Swarm"),
            FALLBACK_PRIMARY,
            "removed configured defaults keep the existing Build fallback"
        );
    }

    #[test]
    fn defensive_role_def_grants_at_most_ten_tools() {
        let def = embedded_default("Careful").expect("Careful embedded default");
        let grants = builtin_tool_names(&def);

        assert!(
            grants.len() <= 10,
            "Careful direct grants should stay small: {grants:?}"
        );
        assert_eq!(
            grants,
            [
                "bash", "edit", "mcp", "question", "read", "schedule", "search", "task", "unlock",
                "write",
            ]
            .into_iter()
            .map(String::from)
            .collect()
        );
    }

    #[test]
    fn defensive_role_def_covers_every_build_tool_by_grant_or_discovery() {
        let build = build_def();
        let careful = embedded_default("Careful").expect("Careful embedded default");
        let build_surface = effective_surface_names(&build);
        let careful_surface = effective_surface_names(&careful);

        let missing: Vec<_> = build_surface
            .difference(&careful_surface)
            .cloned()
            .collect();
        assert!(
            missing.is_empty(),
            "Careful must grant or tier every Build surface tool; missing {missing:?}"
        );
        assert!(
            crate::engine::builtin::default_discoverable_tools_for("Careful")
                .iter()
                .all(|tool| careful_surface.contains(*tool)),
            "Careful discoverable defaults must be present in its declared tools"
        );
    }

    #[test]
    fn defensive_role_is_not_experimental_gated() {
        let tmp = tempfile::tempdir().unwrap();
        let listed = crate::agents::chat_ownable_primaries(tmp.path());

        assert!(BUILTIN_AGENT_NAMES.contains(&"Careful"));
        assert!(is_builtin_primary("Careful"));
        assert!(!is_hidden_primary("Careful"));
        assert!(!is_removed_primary("Careful"));
        assert_eq!(
            embedded_default("Careful")
                .expect("Careful embedded default")
                .mode,
            AgentMode::Primary
        );
        assert!(
            listed.iter().any(|name| name == "Careful"),
            "Careful should be public in the primary list: {listed:?}"
        );
    }

    #[test]
    fn build_def_tool_set_unchanged_by_defensive_role() {
        let build = build_def();

        assert_eq!(
            build.tools,
            Some(
                [
                    "read",
                    "bash",
                    "context_pack",
                    "code",
                    "graph",
                    "search",
                    "change_impact",
                    "lsp",
                    "write",
                    "edit",
                    "unlock",
                    "schedule",
                    "question",
                    "skill",
                    "skill_manage",
                    "harness_list",
                    "harness_invoke",
                    "task",
                    "mcp",
                ]
                .into_iter()
                .map(String::from)
                .collect()
            )
        );
        assert!(build.tool_tiers.is_empty());
    }

    #[test]
    fn history_agent_def_is_subagent_read_only_and_builtin_tiered() {
        let def = embedded_default("history").expect("history embedded default");
        assert_eq!(def.name, "history");
        assert_eq!(def.mode, AgentMode::Subagent);
        assert!(BUILTIN_AGENT_NAMES.contains(&"history"));

        let tools = def.tools.as_ref().expect("history has explicit tools");
        for tool in [
            "read",
            "session_search",
            "session_read",
            "session_lineage_search",
        ] {
            assert!(tools.iter().any(|name| name == tool), "{tool} missing");
        }
        for forbidden in ["task", "spawn", "handoff", "write", "edit", "unlock"] {
            assert!(
                !tools.iter().any(|name| name == forbidden),
                "{forbidden} must not be granted"
            );
        }
        for tool in ["session_search", "session_read", "session_lineage_search"] {
            assert_eq!(def.tool_tiers.get(tool), Some(&ToolTier::Enabled));
        }
    }
}
