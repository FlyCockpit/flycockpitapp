//! Core-invariant validation for user-loadable agent definitions
//! (edited built-ins + custom agents). Enforced at load time with a
//! clear, actionable error per the project error-style (backticks for
//! identifiers/literals).
//!
//! Two invariants gate the editable `tools:` grant
//! (implementation note):
//!
//!   1. **Write-capability is role-driven, not name-bound**
//!      (GOALS §3a / §26 / `project guidance`, prompt
//!      `lock-manager-multi-writer.md`): the file-mutating + lock tools
//!      may be granted to **any write-capable agent** — an agent is a
//!      writer precisely *because* it holds these tools. The single-writer
//!      guarantee that prevents corruption/lost-updates is **not** enforced
//!      by restricting the grant to one hard-coded name (`builder`); it is
//!      enforced by the single in-daemon lock authority (`crate::locks`),
//!      which is path-granular and keyed by `(session, agent)`: concurrent
//!      writers on **disjoint** paths coexist, a **same-path** write across
//!      two writers is serialized/rejected (never a silent no-op), and the
//!      `(session, agent)` suspend-on-handoff / hash-matched-resume
//!      machinery keeps a **single active writer per delegation tree**. The
//!      write-existing-file guard (§3c) holds per `(session, agent)` for
//!      every writer. So this gate no longer rejects a write/lock grant by
//!      agent name — the read-only roles are kept read-only by *not*
//!      granting them the tools, not by a name check here.
//!   2. **Docs-answerer sandbox**: the sandboxed `grep`/`glob` tools are
//!      Docs.2-only (`project guidance`). No user agent may acquire them.
//!
//! Unknown tool names are rejected with the offending name backticked.

use anyhow::{Result, bail};

use super::AgentDef;
use super::ToolTier;

/// The file-mutating + lock tools. Any agent that holds these is a
/// **write-capable** agent (the definition of "writer" is structural —
/// holding these tools — not a hard-coded name). Their writes are
/// arbitrated by the single in-daemon lock authority (`crate::locks`),
/// path-granular and keyed by `(session, agent)`, so multiple write-capable
/// agents coexist on disjoint paths while a same-path write is
/// serialized/rejected. Sourced from the `builder` factory's tool surface in
/// [`crate::engine::builtin`].
pub const LOCK_WRITE_TOOLS: &[&str] = &["write", "edit", "unlock"];

/// The docs-answerer-only sandboxed search tools (Docs.2). Never
/// grantable to a user agent — they exist solely so the docs answerer can
/// explore a cloned dependency without shell access, hard-confined to its
/// package root.
pub const SANDBOX_ONLY_TOOLS: &[&str] = &["grep", "glob"];

/// The recursive fan-out tool (GOALS §24/§26a). Grantable only to the write
/// branch (`bee`) and read-only review branch (`Multireview`/`scout`).
pub const SPAWN_TOOL: &str = "spawn";

const SPAWN_AGENTS: &[&str] = &["bee", "Multireview", "scout"];

/// The structural delegation tools. Never grantable to a delegation child
/// (prompt `parent-granted-tools.md`): a delegated child is a leaf and must
/// report a single result up, so it may not gain the power to spawn its own
/// subagents (`task`) or jump primaries (`start_build`). A stale grant of the
/// retired native `handoff` name fails as unknown-tool rather than via this
/// list. The recursive fan-out exception is [`SPAWN_TOOL`], gated separately.
pub const DELEGATION_TOOLS: &[&str] = &["task", "start_build"];

pub const STRUCTURAL_TOOLS: &[&str] = &[
    "question",
    "return",
    "schedule",
    "task",
    "spawn",
    "defer_to_orchestrator",
    "start_build",
];

/// Tools that may be granted **only to primary (chat-owning) agents** —
/// the external-harness delegation tools (GOALS §6,
/// implementation note). An external harness runs outside
/// cockpit's lock manager and writes to the tree directly (Build mode) or
/// into an isolated worktree (Plan mode); handing that to a leaf subagent
/// would break leaf-termination and the single-writer model, so a
/// subagent-mode agent may not name them. The built-in `Build`/`Plan`
/// factories register them directly; this gate guards the user-authored
/// `tools:` path.
pub const PRIMARY_ONLY_TOOLS: &[&str] = &["harness_list", "harness_invoke", "start_build"];

/// Every tool name a user-facing agent may legitimately *name* in its
/// `tools:` frontmatter. This is the union of:
///   - the read/inspect tools every agent can use,
///   - the codebase-intelligence tools (GOALS §21),
///   - the interactive/structural tools (`task`, `skill`, `question`,
///     `schedule`),
///   - the cross-session recall tools (registered only on interactive
///     spawns, but a valid name to grant),
///   - the write/lock tools (grantable to any write-capable agent;
///     correctness is arbitrated by the lock manager keyed by
///     `(session, agent)`, not by an agent-name check here),
///   - the sandbox tools (Docs.2-only — known names, rejected by the
///     sandbox check).
///
/// User-defined custom-bash tools (`webfetch`/`websearch`/…) are *not*
/// listed: they are config-driven and resolved separately onto the
/// toolbox, so naming them in `tools:` is not how they're granted.
pub fn known_tool_names() -> &'static [&'static str] {
    crate::engine::builtin::known_agent_tool_names()
}

fn retired_lock_verb_replacement(tool: &str) -> Option<&'static str> {
    // Deliberate retired-name diagnostics for pre-collapse configs; keep in
    // sync with the lock-protocol-collapse-to-edit-write prompt.
    match tool {
        "readlock" => Some("read"),
        "writeunlock" => Some("write"),
        "editunlock" => Some("edit"),
        _ => None,
    }
}

/// Validate a per-delegation **tool grant** (prompt `parent-granted-tools.md`):
/// a parent attaching extra tools to a single `task` delegation. Each granted
/// name is checked against the **same** core invariants a user-authored
/// `tools:` grant is — so a grant can never smuggle a capability past a role
/// invariant. Returns `Ok(())` when every name is admissible, else an `Err`
/// whose message names the offending tool (backticked) and the rule it breaks.
///
/// `target_name`/`target_mode` are the delegation target's own identity (its
/// resolved [`AgentDef`]), so the spawn-only / primary-only rules are
/// evaluated for *that* agent — e.g. the recursive fan-out tool to a
/// non-fan-out agent is rejected, and the external-harness tools to a
/// subagent are rejected. Write/lock tools are **not** grantable per
/// delegation at all: write-capability is a property of an agent's *base
/// definition* (governed by [`validate_invariants`] and arbitrated at runtime
/// by the `(session, agent)` lock manager), not something a parent confers
/// ad-hoc — so granting one to a read-only-role child (e.g. `explore`) is
/// rejected. The offending grant is **never** silently dropped.
pub fn validate_grant(
    target_name: &str,
    target_mode: super::AgentMode,
    grant: &[String],
) -> Result<()> {
    let known = known_tool_names();
    for tool in grant {
        if let Some(replacement) = retired_lock_verb_replacement(tool) {
            bail!(
                "delegation to `{target_name}` granted retired lock tool `{tool}`; use `{replacement}` instead"
            );
        }
        if !known.contains(&tool.as_str()) {
            bail!("delegation to `{target_name}` granted unknown tool `{tool}`");
        }
        // Delegation tools are never grantable: handing a child the power to
        // spawn further work would break leaf-termination — the child is a
        // leaf and must report one result up. (`spawn` is the documented
        // exception, gated to recursive fan-out agents below.)
        if DELEGATION_TOOLS.contains(&tool.as_str()) {
            bail!(
                "delegation to `{target_name}` may not be granted the delegation tool `{tool}` — a delegated child is a leaf and may not spawn further work (leaf-termination rule)"
            );
        }
        if SANDBOX_ONLY_TOOLS.contains(&tool.as_str()) {
            bail!(
                "delegation to `{target_name}` may not be granted the docs-answerer-only sandboxed tool `{tool}`"
            );
        }
        if tool == SPAWN_TOOL && !SPAWN_AGENTS.contains(&target_name) {
            bail!(
                "delegation to `{target_name}` may not be granted the recursive fan-out tool `{tool}` — only `bee` and multireview/scout fan out (leaf-termination exception, GOALS §24)"
            );
        }
        // Write/lock tools are not grantable per delegation: write-capability
        // is a property of an agent's *base definition* (a write-capable agent
        // holds these in its own `tools:`, validated by `validate_invariants`),
        // not something a parent confers ad-hoc. Granting one to a
        // read-only-role child (e.g. `explore`) would violate that role, so it
        // is rejected here — name-agnostically. Concurrency among the agents
        // that legitimately hold these tools is arbitrated by the lock manager
        // (`crate::locks`, keyed by `(session, agent)`): disjoint paths coexist,
        // a same-path write is serialized/rejected, suspend/resume keeps one
        // active writer per tree, and the §3c guard holds per writer.
        if LOCK_WRITE_TOOLS.contains(&tool.as_str()) {
            bail!(
                "delegation to `{target_name}` may not be granted the write/lock tool `{tool}` — write-capability is set in an agent's base definition, not conferred per delegation"
            );
        }
        if PRIMARY_ONLY_TOOLS.contains(&tool.as_str())
            && target_mode == crate::agents::AgentMode::Subagent
        {
            bail!(
                "delegation to `{target_name}` may not be granted the external-harness tool `{tool}` — it is for primary (chat-owning) agents only (leaf-termination rule)"
            );
        }
    }
    Ok(())
}

/// Validate the issue-#75 posture fields (`capabilities`, `toolSteering`,
/// `contextPolicy`) declared on an [`AgentDef`]. These are additive in Stage 1
/// and apply to both legacy and v2 definitions. Unknown capability names are
/// already rejected by serde (the enum is closed), so this checks the
/// `autoCompactPct` range and emits a lint-level warning (returned via the
/// load-warning channel by the caller) when `forkContext` or
/// `scopedParallelWrite` is granted to a def whose model slots suggest only
/// local/small models.
pub(crate) fn validate_posture_fields(def: &AgentDef) -> Result<()> {
    use super::{AgentCapability, ContextPolicy};
    if let Some(policy) = &def.context_policy {
        validate_context_policy(policy)?;
    }
    if let Some(caps) = &def.capabilities {
        // The enum is closed (serde rejects unknown names), so the only
        // set-level check is the small-model lint below. Capability names
        // are already constrained to the four variants.
        let _ = caps;
    }
    Ok(())
}

fn validate_context_policy(policy: &ContextPolicy) -> Result<()> {
    if let Some(pct) = policy.auto_compact_pct {
        if !(10..=95).contains(&pct) {
            bail!("contextPolicy.autoCompactPct must be between 10 and 95 (got `{pct}`)");
        }
    }
    Ok(())
}

/// Lint-level (non-fatal) warning when `forkContext` or
/// `scopedParallelWrite` is granted to a def whose model slots suggest only
/// local/small models. Returns the warning text, or `None` when the grant is
/// plausible. Surfaced through the load-warning channel rather than failing
/// load.
pub(crate) fn small_model_capability_warning(def: &AgentDef) -> Option<String> {
    use super::AgentCapability;
    let caps = def.capabilities.as_ref()?;
    if !caps.contains(&AgentCapability::ForkContext)
        && !caps.contains(&AgentCapability::ScopedParallelWrite)
    {
        return None;
    }
    // Heuristic: only warn when the author actually suggested at least one
    // model and every suggestion is explicitly local/small. An empty
    // suggestion list leaves model choice to host policy and is not evidence
    // of a small-model-only definition.
    let vnext = def.vnext.as_ref()?;
    let mut saw_suggestion = false;
    let only_local_or_small = vnext.model_slots.values().all(|slot| {
        slot.suggested_models.iter().all(|recommendation| {
            saw_suggestion = true;
            let identity = recommendation.upstream_identity.to_ascii_lowercase();
            slot.locality == super::ModelLocality::Local
                || identity.contains("/local/")
                || identity.starts_with("local/")
                || identity.contains("small")
        })
    });
    if !saw_suggestion || !only_local_or_small {
        return None;
    }
    Some(format!(
        "agent `{}` grants `forkContext` or `scopedParallelWrite` but its model slots suggest only local/small models — these capabilities are unlikely to be exercised",
        def.name
    ))
}

/// Validate `def` against the core invariants. Returns `Ok(())` when the
/// definition is admissible, else an `Err` whose message names the
/// specific reason (the offending tool / agent, backticked). The
/// offending tool is **never** silently stripped.
pub fn validate_invariants(def: &AgentDef) -> Result<()> {
    validate_posture_fields(def)?;
    if let Some(vnext) = &def.vnext {
        // v2 declarations are deliberately authority-free. Their own closed
        // schema is the only applicable definition-level invariant; legacy
        // tool/role checks below must not accidentally reinterpret them.
        return vnext.validate();
    }
    def.goal_supervision.validate()?;

    let known = known_tool_names();

    // Per-agent tool-description overrides (prompt `per-agent-tool-definitions.md`):
    // each key must name a known tool. When the agent carries an explicit
    // `tools:` grant the key must also be in it — overriding the description of
    // a tool the agent doesn't hold is a mistake (the override would be inert),
    // so we reject it loudly rather than silently dropping it. With no explicit
    // grant the agent inherits its role-default surface, so we can only check
    // the name is known; an inert key there is harmless (it lands on the box
    // only if a matching tool is present at construction).
    for tool in def.tool_descriptions.keys() {
        if let Some(replacement) = retired_lock_verb_replacement(tool) {
            bail!(
                "agent `{}` overrides retired lock tool `{tool}`; use `{replacement}` instead",
                def.name
            );
        }
        if !known.contains(&tool.as_str()) {
            bail!(
                "agent `{}` overrides the description of unknown tool `{tool}`",
                def.name
            );
        }
        if known.contains(&tool.as_str())
            && let Some(grant) = &def.tools
            && !grant.iter().any(|g| g == tool)
        {
            bail!(
                "agent `{}` overrides the description of tool `{tool}` it does not grant in `tools:`",
                def.name
            );
        }
    }

    for (tool, tier) in &def.tool_tiers {
        if let Some(replacement) = retired_lock_verb_replacement(tool) {
            bail!(
                "agent `{}` tiers retired lock tool `{tool}`; use `{replacement}` instead",
                def.name
            );
        }
        if !known.contains(&tool.as_str()) && *tier != ToolTier::Disabled {
            bail!("agent `{}` tiers unknown tool `{tool}`", def.name);
        }
        if let Some(grant) = &def.tools
            && !grant.iter().any(|g| g == tool)
        {
            bail!(
                "agent `{}` tiers tool `{tool}` it does not grant in `tools:`",
                def.name
            );
        }
        if *tier == ToolTier::Discoverable && STRUCTURAL_TOOLS.contains(&tool.as_str()) {
            bail!(
                "agent `{}` may not tier structural tool `{tool}` as `discoverable`",
                def.name
            );
        }
        if *tier == ToolTier::Disabled && STRUCTURAL_TOOLS.contains(&tool.as_str()) {
            bail!(
                "agent `{}` may not tier structural tool `{tool}` as `disabled`",
                def.name
            );
        }
        if *tier == ToolTier::Discoverable && LOCK_WRITE_TOOLS.contains(&tool.as_str()) {
            bail!(
                "agent `{}` may not tier write/lock tool `{tool}` as `discoverable`",
                def.name
            );
        }
        if *tier == ToolTier::Disabled && LOCK_WRITE_TOOLS.contains(&tool.as_str()) {
            bail!(
                "agent `{}` may not tier write/lock tool `{tool}` as `disabled`",
                def.name
            );
        }
    }

    let effective_tools = effective_grant_for_invariants(def);
    validate_discoverable_tools_have_mcp(def, &effective_tools)?;

    let Some(tools) = &def.tools else {
        // No explicit tool grant — the agent inherits its role-default
        // surface from the factory; nothing further to validate here.
        return Ok(());
    };

    for tool in tools {
        // Unknown tool name.
        if let Some(replacement) = retired_lock_verb_replacement(tool) {
            bail!(
                "agent `{}` requests retired lock tool `{tool}`; use `{replacement}` instead",
                def.name
            );
        }
        if !known.contains(&tool.as_str()) {
            bail!("agent `{}` requests unknown tool `{tool}`", def.name);
        }
        // Docs-answerer sandbox: never grantable to a user agent.
        if SANDBOX_ONLY_TOOLS.contains(&tool.as_str()) {
            bail!(
                "agent `{}` may not use the docs-answerer-only sandboxed tool `{tool}`",
                def.name
            );
        }
        // Recursive fan-out: grantable only to the write branch (`bee`) and
        // read-only review branch (`Multireview`/`scout`).
        if tool == SPAWN_TOOL && !SPAWN_AGENTS.contains(&def.name.as_str()) {
            bail!(
                "agent `{}` may not hold the recursive fan-out tool `{tool}` — only `bee` and `Multireview`/`scout` fan out (leaf-termination exception, GOALS §24/§26a)",
                def.name
            );
        }
        if matches!(def.name.as_str(), "scout" | "Multireview")
            && LOCK_WRITE_TOOLS.contains(&tool.as_str())
        {
            bail!(
                "agent `{}` must stay read-only and may not hold write/lock tool `{tool}`",
                def.name
            );
        }
        // Write/lock tools are role-driven, not name-bound: any agent that
        // names them is a write-capable agent. The single-writer guarantee is
        // upheld by the lock manager (`crate::locks`, keyed by
        // `(session, agent)`), not by a name check here — concurrent writers
        // coexist on disjoint paths, a same-path write is serialized/rejected,
        // and the §3c write-existing-file guard holds per writer.
        // Primary-only: external-harness delegation never on a subagent.
        if PRIMARY_ONLY_TOOLS.contains(&tool.as_str())
            && def.mode == crate::agents::AgentMode::Subagent
        {
            bail!(
                "agent `{}` may not hold the external-harness tool `{tool}` — it is for primary (chat-owning) agents only (leaf-termination rule)",
                def.name
            );
        }
        if tool == "start_build" && def.name != "Plan" {
            bail!(
                "agent `{}` may not use `start_build` — only `Plan` can hand a plan document to `Build`",
                def.name
            );
        }
    }
    Ok(())
}

fn effective_grant_for_invariants(def: &AgentDef) -> Vec<String> {
    if let Some(tools) = &def.tools {
        return tools.clone();
    }
    crate::agents::embedded_default(&def.name)
        .and_then(|embedded| embedded.tools)
        .unwrap_or_default()
}

fn validate_discoverable_tools_have_mcp(def: &AgentDef, tools: &[String]) -> Result<()> {
    if tools.iter().any(|tool| tool == "mcp") {
        return Ok(());
    }
    for tool in tools {
        let tier = def
            .tool_tiers
            .get(tool)
            .copied()
            .unwrap_or_else(|| discoverable_default_tier(&def.name, tool));
        if tier == ToolTier::Discoverable {
            bail!(
                "agent `{}` tiers tool `{tool}` as `discoverable` but does not grant `mcp`, so the tool is unreachable — grant `mcp` or tier it `enabled`",
                def.name
            );
        }
    }
    Ok(())
}

fn discoverable_default_tier(agent_name: &str, tool: &str) -> ToolTier {
    if crate::engine::builtin::default_discoverable_tools_for(agent_name).contains(&tool) {
        ToolTier::Discoverable
    } else {
        ToolTier::Enabled
    }
}

#[cfg(test)]
mod grant_tests {
    use super::*;
    use crate::agents::{
        AgentMode, DelegationPolicy, DelegationTarget, ExecutionKind, ModelCapability,
        ModelLocality, ModelSlot, VnextAgentDef,
    };

    fn g(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn tiered_def(
        name: &str,
        tools: &[&str],
        tool: &str,
        tier: ToolTier,
    ) -> crate::agents::AgentDef {
        let mut tool_tiers = std::collections::BTreeMap::new();
        tool_tiers.insert(tool.to_string(), tier);
        crate::agents::AgentDef {
            name: name.to_string(),
            description: "custom".to_string(),
            mode: AgentMode::Primary,
            model: None,
            temperature: None,
            tools: Some(g(tools)),
            tool_tiers,
            tool_descriptions: std::collections::BTreeMap::new(),
            scan_tool_results: None,
            goal_supervision: crate::agents::GoalSettingsOverride::default(),
            permission: None,
            fork_eligible: false,
            capabilities: None,
            tool_steering: None,
            context_policy: None,
            vnext: None,
            prompt: "body".to_string(),
            prompt_overrides: std::collections::BTreeMap::new(),
            source: std::path::PathBuf::new(),
        }
    }

    /// Granting MCP to a read-only noninteractive child (`explore`) is the
    /// primary use case and must be admitted (prompt `parent-granted-tools.md`).
    #[test]
    fn grants_mcp_to_explore() {
        assert!(validate_grant("explore", AgentMode::Subagent, &g(&["mcp"])).is_ok());
    }

    /// An empty grant is always admissible — the common no-grant delegation.
    #[test]
    fn empty_grant_ok() {
        assert!(validate_grant("explore", AgentMode::Subagent, &[]).is_ok());
    }

    /// Write/lock tools are not grantable per delegation: write-capability is
    /// a base-definition property, not a parent-conferred grant. A write grant
    /// to a read-only-role child (`explore`) — or any target — is rejected,
    /// never silently honored. Name-agnostic (no hard-coded writer name).
    #[test]
    fn rejects_write_lock_grant_to_any_target() {
        let err = validate_grant("explore", AgentMode::Subagent, &g(&["write"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("write"), "{err}");
        assert!(err.contains("base definition"), "{err}");
        // Rejected regardless of the target name (not a `builder`-name check).
        assert!(
            validate_grant("custom-writer", AgentMode::Subagent, &g(LOCK_WRITE_TOOLS)).is_err()
        );
    }

    /// The recursive fan-out tool may not be granted to a non-fan-out agent.
    #[test]
    fn rejects_spawn_to_non_swarm() {
        let err = validate_grant("explore", AgentMode::Subagent, &g(&["spawn"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("spawn"), "{err}");
    }

    /// A delegation tool may not be granted to a leaf child — that would break
    /// leaf-termination.
    #[test]
    fn rejects_delegation_tools() {
        for t in ["task", "start_build"] {
            let err = validate_grant("explore", AgentMode::Subagent, &g(&[t]))
                .unwrap_err()
                .to_string();
            assert!(err.contains(t), "{err}");
            assert!(err.contains("leaf-termination"), "{err}");
        }
        // Retired native `handoff` is not materializable; a stale grant fails
        // as a normal unknown tool (no dedicated compatibility rejection path).
        let err = validate_grant("explore", AgentMode::Subagent, &g(&["handoff"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("handoff"), "{err}");
        assert!(
            err.contains("unknown tool"),
            "stale handoff grant must use unknown-tool path, not a special-case: {err}"
        );
        assert!(
            !err.contains("leaf-termination"),
            "retired handoff must not use DELEGATION_TOOLS leaf-termination path: {err}"
        );
    }

    /// The external-harness tools are primary-only — rejected for a subagent.
    #[test]
    fn rejects_primary_only_to_subagent() {
        let err = validate_grant("explore", AgentMode::Subagent, &g(&["harness_invoke"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("harness_invoke"), "{err}");
    }

    /// An unknown tool name is rejected.
    #[test]
    fn rejects_unknown() {
        let err = validate_grant("explore", AgentMode::Subagent, &g(&["nope"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("nope"), "{err}");
    }

    #[test]
    fn agent_def_naming_retired_lock_verb_names_replacement() {
        // Deliberate retired-name coverage for the tool collapse diagnostics.
        for (retired, replacement) in [
            ("readlock", "read"),
            ("writeunlock", "write"),
            ("editunlock", "edit"),
        ] {
            let def = tiered_def("legacy-writer", &[retired], retired, ToolTier::Enabled);
            let err = validate_invariants(&def)
                .expect_err("retired lock tool name must be rejected")
                .to_string();

            assert!(err.contains(retired), "{err}");
            assert!(err.contains(replacement), "{err}");
            assert!(err.contains("retired lock tool"), "{err}");
        }
    }

    #[test]
    fn discoverable_without_mcp_grant_is_rejected() {
        let def = tiered_def(
            "custom-discoverable",
            &["read", "code"],
            "code",
            ToolTier::Discoverable,
        );

        let err = validate_invariants(&def)
            .expect_err("discoverable tool without mcp must be rejected")
            .to_string();

        assert!(err.contains("custom-discoverable"), "{err}");
        assert!(err.contains("code"), "{err}");
        assert!(err.contains("mcp"), "{err}");
    }

    #[test]
    fn discoverable_with_mcp_grant_is_accepted() {
        let with_mcp = tiered_def(
            "custom-discoverable",
            &["read", "code", "mcp"],
            "code",
            ToolTier::Discoverable,
        );
        let builtin = tiered_def(
            "custom-enabled",
            &["read", "code"],
            "code",
            ToolTier::Enabled,
        );
        let disabled = tiered_def(
            "custom-disabled",
            &["read", "code"],
            "code",
            ToolTier::Disabled,
        );

        validate_invariants(&with_mcp).expect("mcp makes discoverable tool reachable");
        validate_invariants(&builtin).expect("enabled tier is directly reachable");
        validate_invariants(&disabled).expect("disabled tier is not discoverable");
    }

    #[test]
    fn agent_vnext_invariants_apply_closed_schema_not_legacy_leaf_rules() {
        let mut def = tiered_def(
            "vnext-reviewer",
            &["not-a-real-tool"],
            "not-a-real-tool",
            ToolTier::Enabled,
        );
        def.vnext = Some(VnextAgentDef {
            schema_version: crate::agents::SCHEMA_VERSION,
            agent_id: "acme/reviewer".to_string(),
            execution_kind: ExecutionKind::Coding,
            model_slots: std::collections::BTreeMap::from([(
                "primary".to_string(),
                ModelSlot {
                    purpose: "Review source".to_string(),
                    min_context_tokens: 1,
                    required_capabilities: vec![ModelCapability::TextGeneration],
                    locality: ModelLocality::Any,
                    allow_default_fallback: false,
                    suggested_models: Vec::new(),
                },
            )]),
            delegation: DelegationPolicy::default(),
            questions: None,
            verification: None,
        });
        // A v2 definition has no user-authored tool authority, so legacy tool
        // validation must not reinterpret its ignored internal fields.
        validate_invariants(&def).unwrap();

        let vnext = def.vnext.as_mut().unwrap();
        vnext.execution_kind = ExecutionKind::Computer;
        vnext.delegation = DelegationPolicy {
            allowed_children: vec![],
            max_descendant_depth: Some(1),
            max_concurrent_children: Some(1),
            targets: vec![DelegationTarget::SameRoot],
        };
        let error = validate_invariants(&def).unwrap_err().to_string();
        assert!(error.contains("computer"), "{error}");
    }
}
