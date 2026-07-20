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
pub const LOCK_WRITE_TOOLS: &[&str] = &["readlock", "writeunlock", "editunlock", "unlock"];

/// The docs-answerer-only sandboxed search tools (Docs.2). Never
/// grantable to a user agent — they exist solely so the docs answerer can
/// explore a cloned dependency without shell access, hard-confined to its
/// package root.
pub const SANDBOX_ONLY_TOOLS: &[&str] = &["grep", "glob"];

/// The recursive fan-out tool (GOALS §24/§26a). Grantable only to the write
/// branch (`Swarm`/`bee`) and read-only review branch (`Multireview`/`scout`).
pub const SPAWN_TOOL: &str = "spawn";

const SPAWN_AGENTS: &[&str] = &["Swarm", "bee", "Multireview", "scout"];

/// The structural delegation/handoff tools. Never grantable to a delegation
/// child (prompt `parent-granted-tools.md`): a delegated child is a leaf and
/// must report a single result up, so it may not gain the power to spawn its
/// own subagents (`task`) or hand off the conversation (`handoff`). The
/// recursive-`Swarm` exception is [`SPAWN_TOOL`], gated separately.
pub const DELEGATION_TOOLS: &[&str] = &["task", "handoff", "start_build"];

pub const STRUCTURAL_TOOLS: &[&str] = &[
    "question",
    "handoff",
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
/// non-`Swarm` agent is rejected, and the external-harness tools to a
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
        if !known.contains(&tool.as_str()) {
            bail!("delegation to `{target_name}` granted unknown tool `{tool}`");
        }
        // Delegation/handoff tools are never grantable: handing a child the
        // power to spawn or hand off would break leaf-termination — the child
        // is a leaf and must report one result up. (`spawn` is the
        // documented exception, gated to `Swarm` below.)
        if DELEGATION_TOOLS.contains(&tool.as_str()) {
            bail!(
                "delegation to `{target_name}` may not be granted the delegation tool `{tool}` — a delegated child is a leaf and may not spawn or hand off (leaf-termination rule)"
            );
        }
        if SANDBOX_ONLY_TOOLS.contains(&tool.as_str()) {
            bail!(
                "delegation to `{target_name}` may not be granted the docs-answerer-only sandboxed tool `{tool}`"
            );
        }
        if tool == SPAWN_TOOL && !SPAWN_AGENTS.contains(&target_name) {
            bail!(
                "delegation to `{target_name}` may not be granted the recursive fan-out tool `{tool}` — only `Swarm`/`bee` fan out (leaf-termination exception, GOALS §24)"
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

/// Validate `def` against the core invariants. Returns `Ok(())` when the
/// definition is admissible, else an `Err` whose message names the
/// specific reason (the offending tool / agent, backticked). The
/// offending tool is **never** silently stripped.
pub fn validate_invariants(def: &AgentDef) -> Result<()> {
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
        if *tier == ToolTier::Discoverable && LOCK_WRITE_TOOLS.contains(&tool.as_str()) {
            bail!(
                "agent `{}` may not tier write/lock tool `{tool}` as `discoverable`",
                def.name
            );
        }
    }

    let Some(tools) = &def.tools else {
        // No explicit tool grant — the agent inherits its role-default
        // surface from the factory; nothing further to validate here.
        return Ok(());
    };

    for tool in tools {
        // Unknown tool name.
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
        // Recursive fan-out: grantable only to the write branch
        // (`Swarm`/`bee`) and read-only review branch (`Multireview`/`scout`).
        if tool == SPAWN_TOOL && !SPAWN_AGENTS.contains(&def.name.as_str()) {
            bail!(
                "agent `{}` may not hold the recursive fan-out tool `{tool}` — only `Swarm`/`bee` and `Multireview`/`scout` fan out (leaf-termination exception, GOALS §24/§26a)",
                def.name
            );
        }
        if matches!(def.name.as_str(), "scout" | "Multireview")
            && (LOCK_WRITE_TOOLS.contains(&tool.as_str())
                || matches!(
                    tool.as_str(),
                    "write" | "edit" | "writeunlock" | "editunlock"
                ))
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

#[cfg(test)]
mod grant_tests {
    use super::*;
    use crate::agents::AgentMode;

    fn g(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
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
        let err = validate_grant("explore", AgentMode::Subagent, &g(&["writeunlock"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("writeunlock"), "{err}");
        assert!(err.contains("base definition"), "{err}");
        // Rejected regardless of the target name (not a `builder`-name check).
        assert!(
            validate_grant("custom-writer", AgentMode::Subagent, &g(LOCK_WRITE_TOOLS)).is_err()
        );
    }

    /// The recursive fan-out tool may not be granted to a non-`Swarm` agent
    /// (leaf-termination exception is Swarm-only).
    #[test]
    fn rejects_spawn_to_non_swarm() {
        let err = validate_grant("explore", AgentMode::Subagent, &g(&["spawn"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("spawn"), "{err}");
    }

    /// A delegation/handoff tool may not be granted to a leaf child — that
    /// would break leaf-termination.
    #[test]
    fn rejects_delegation_tools() {
        for t in ["task", "handoff"] {
            let err = validate_grant("explore", AgentMode::Subagent, &g(&[t]))
                .unwrap_err()
                .to_string();
            assert!(err.contains(t), "{err}");
            assert!(err.contains("leaf-termination"), "{err}");
        }
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
}
