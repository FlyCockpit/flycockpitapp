//! Step five of onboarding: **create your first agent**.
//!
//! Providers gave us models; now we shape the agent that flies them. This is a
//! nested wizard — a handful of focused screens that each edit one facet of a
//! shared [`AgentDraft`], with the same back/forward, mouse, and palette
//! conventions as the earlier steps. The screens, in order:
//!
//! 1. [`basics`]   — name the agent.
//! 2. [`models`]   — pick which models it may use, and the default.
//! 3. [`trust`]    — trusted vs. untrusted (secret/sealed-value redaction).
//! 4. [`optimizations`] — auto-prune, interactive subagents, recursion depth,
//!    tool steering, goal-completion skeptics, and (nested) self-verify.
//! 5. [`tools`]    — grant tools, ordered required → suggested → other, with a
//!    model chooser for tools that need one.
//! 6. [`subagents`] — define subagents (including a trusted one that may set
//!    sealed values), each with its own models and tools.
//! 7. [`review`]   — read the whole thing back and create it.
//!
//! Everything here is a faithful *sketch* of `cockpit_core`'s agent
//! definition surface (`AgentDef` / launch-vNext `delegation` + `verification`
//! + `capabilities`), not a live control plane: no agent is actually spawned.

mod basics;
mod models;
mod optimizations;
mod review;
mod selfverify;
mod subagents;
mod tools;
mod trust;
mod ui;

use std::io::Stdout;

use anyhow::Result;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

/// A model the agent may be granted, discovered while verifying a provider.
/// The catalog the agent step works from is the union of these across every
/// provider onboarding added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AvailableModel {
    pub provider_id: &'static str,
    pub provider_display: &'static str,
    pub model_id: String,
    pub display: Option<String>,
}

impl AvailableModel {
    /// Best human label: the display name if the endpoint gave one, else the id.
    pub(super) fn label(&self) -> &str {
        self.display.as_deref().unwrap_or(&self.model_id)
    }
}

/// How the agent step finished, handed back to the onboarding wizard.
pub(super) enum Outcome {
    Created(AgentSummary),
    /// Step back to the provider flow (e.g. to add another provider first).
    Back,
    Quit,
}

/// Navigation intent every agent screen returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Nav {
    Next,
    Back,
    Quit,
}

/// Suggestion tier for a tool, which drives ordering and the default grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tier {
    /// Always granted; can't be turned off.
    Required,
    /// Granted by default.
    Suggested,
    /// Off by default (powerful or niche).
    Other,
}

impl Tier {
    fn heading(self) -> &'static str {
        match self {
            Tier::Required => "Required",
            Tier::Suggested => "Suggested",
            Tier::Other => "Not suggested",
        }
    }
}

/// One entry in the built-in tool catalog.
pub(super) struct ToolInfo {
    pub id: &'static str,
    pub display: &'static str,
    pub hint: &'static str,
    pub tier: Tier,
    /// When set, the tool can't run without a model in this role (e.g. a
    /// vision model to describe images). It stays disabled until one is chosen.
    pub requires_model: Option<&'static str>,
}

/// The catalog, authored in tier order (required first, then suggested, then
/// not-suggested) so a plain iteration renders the list the wizard wants.
pub(super) const TOOLS: &[ToolInfo] = &[
    ToolInfo {
        id: "read",
        display: "Read files",
        hint: "Read files and directories in the workspace.",
        tier: Tier::Required,
        requires_model: None,
    },
    ToolInfo {
        id: "write",
        display: "Write & edit files",
        hint: "Create files and apply edits.",
        tier: Tier::Required,
        requires_model: None,
    },
    ToolInfo {
        id: "shell",
        display: "Run commands",
        hint: "Execute shell commands in the workspace.",
        tier: Tier::Required,
        requires_model: None,
    },
    ToolInfo {
        id: "search",
        display: "Search the codebase",
        hint: "Ripgrep-style content and filename search.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "fetch",
        display: "Fetch URLs",
        hint: "Retrieve a URL and read it as text.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "websearch",
        display: "Search the web",
        hint: "Run a web search and read the result snippets.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "todo",
        display: "Track a task list",
        hint: "Maintain a structured to-do list for the session.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "task",
        display: "Delegate to subagents",
        hint: "Delegate to a subagent synchronously, or run it in the background. Recursion depth gates further nesting.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "timer",
        display: "Set timers & wait",
        hint: "Schedule a one-shot timer or a recurring loop, then wait on it.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "background",
        display: "Run background commands",
        hint: "Start a shell command in the background, then tail its output or cancel it.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "question",
        display: "Ask the user",
        hint: "Pause to ask the user a structured multiple-choice question.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "lsp",
        display: "Code diagnostics (LSP)",
        hint: "Pull language-server diagnostics and jump to definitions.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "monty",
        display: "Monty Sandbox (required for MCPs)",
        hint: "Run Python in the in-process sandbox VM; hosts MCP servers.",
        tier: Tier::Suggested,
        requires_model: None,
    },
    ToolInfo {
        id: "describe_image",
        display: "Describe images",
        hint: "Caption screenshots and images.",
        tier: Tier::Suggested,
        requires_model: Some("vision model"),
    },
    ToolInfo {
        id: "escalate",
        display: "Request elevated access",
        hint: "Ask the user to grant elevated command or path access. Powerful; off by default.",
        tier: Tier::Other,
        requires_model: None,
    },
    ToolInfo {
        id: "computer_use",
        display: "Control the computer",
        hint: "Move the mouse, type, and take screenshots. Powerful; off by default.",
        tier: Tier::Other,
        requires_model: None,
    },
    ToolInfo {
        id: "transcribe_audio",
        display: "Transcribe audio",
        hint: "Turn audio clips into text.",
        tier: Tier::Other,
        requires_model: Some("speech-to-text model"),
    },
];

/// Self-verify applies to three kinds of risky action, each configured
/// independently. Index order matches [`AgentDraft::self_verify`].
pub(super) const SURFACES: [&str; 3] = ["Writes & edits", "Commands", "Monty"];

/// How verbose tool and MCP descriptions are for this agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Steering {
    Terse,
    Verbose,
}

impl Steering {
    fn label(self) -> &'static str {
        match self {
            Steering::Terse => "terse",
            Steering::Verbose => "verbose",
        }
    }

    fn toggled(self) -> Self {
        match self {
            Steering::Terse => Steering::Verbose,
            Steering::Verbose => Steering::Terse,
        }
    }
}

/// Self-verify configuration for a single action surface.
///
/// A surface is verified by any mix of the agent's *own* model (which re-uses
/// the warm prompt cache) and a panel of *other* models. It is "off" only when
/// nothing verifies it. There is no separate same-vs-multi mode: the agent's
/// own model is just one selectable verifier alongside the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SurfaceVerify {
    /// Copies run by the agent's own model — cheap, the cache stays warm.
    pub same_copies: u8,
    /// Per-catalog-model copy counts for other verifiers (0 = unused).
    pub copies: Vec<u8>,
}

impl SurfaceVerify {
    fn new(n_models: usize, on: bool) -> Self {
        Self {
            same_copies: if on { 1 } else { 0 },
            copies: vec![0; n_models],
        }
    }

    /// Nothing verifies this surface.
    pub(super) fn is_off(&self) -> bool {
        self.same_copies == 0 && self.copies.iter().all(|&c| c == 0)
    }

    /// Copies across the *other* (non-same) models.
    pub(super) fn other_copies(&self) -> u32 {
        self.copies.iter().map(|&c| u32::from(c)).sum()
    }

    /// How many distinct *other* models carry at least one copy.
    pub(super) fn other_models(&self) -> usize {
        self.copies.iter().filter(|&&c| c > 0).count()
    }

    /// One-line description for the optimizations row and the review screen.
    pub(super) fn describe(&self) -> String {
        if self.is_off() {
            return "off".to_string();
        }
        let mut parts = Vec::new();
        if self.same_copies > 0 {
            parts.push(format!("same model \u{d7}{}", self.same_copies));
        }
        let others = self.other_models();
        if others > 0 {
            let copies = self.other_copies();
            parts.push(format!(
                "{others} other {}, {copies} {}",
                plural(others as u32, "model", "models"),
                plural(copies, "copy", "copies"),
            ));
        }
        parts.join(" + ")
    }
}

/// How a tool is granted. Enabled tools sit in the prompt, so flipping to or
/// from that state busts the cache; discoverable ↔ disabled does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ToolGrant {
    Enabled,
    Discoverable,
    Disabled,
}

impl ToolGrant {
    fn cycle(self) -> Self {
        match self {
            ToolGrant::Enabled => ToolGrant::Discoverable,
            ToolGrant::Discoverable => ToolGrant::Disabled,
            ToolGrant::Disabled => ToolGrant::Enabled,
        }
    }

    fn label(self) -> &'static str {
        match self {
            ToolGrant::Enabled => "enabled",
            ToolGrant::Discoverable => "discoverable",
            ToolGrant::Disabled => "disabled",
        }
    }

    fn is_enabled(self) -> bool {
        matches!(self, ToolGrant::Enabled)
    }

    fn breaks_cache(from: Self, to: Self) -> bool {
        from.is_enabled() != to.is_enabled()
    }
}

/// One tool's grant state on an agent (or subagent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ToolState {
    pub grant: ToolGrant,
    /// Chosen model (catalog index) for a model-gated tool.
    pub model: Option<usize>,
}

/// A subagent definition attached to the primary agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Subagent {
    pub name: String,
    /// Trusted subagents may read sealed values (e.g. to set one up).
    pub trusted: bool,
    pub model_allowed: Vec<bool>,
    pub default_model: Option<usize>,
    pub tools: Vec<ToolState>,
}

impl Subagent {
    fn new(catalog: &[AvailableModel]) -> Self {
        let (model_allowed, default_model) = default_models(catalog.len());
        Self {
            name: String::new(),
            trusted: false,
            model_allowed,
            default_model,
            tools: default_tools(),
        }
    }
}

/// The whole agent, accumulated across the wizard's screens.
pub(super) struct AgentDraft {
    pub name: String,
    pub model_allowed: Vec<bool>,
    pub default_model: Option<usize>,
    pub trusted: bool,
    pub autoprune: bool,
    pub interactive_subagents: bool,
    pub max_recursion: u8,
    pub steering: Steering,
    pub goal_skeptics: u8,
    /// One entry per [`SURFACES`] surface.
    pub self_verify: Vec<SurfaceVerify>,
    /// One entry per [`TOOLS`] tool.
    pub tools: Vec<ToolState>,
    pub subagents: Vec<Subagent>,
}

impl AgentDraft {
    fn new(catalog: &[AvailableModel]) -> Self {
        let (model_allowed, default_model) = default_models(catalog.len());
        let n = catalog.len();
        Self {
            name: String::new(),
            model_allowed,
            default_model,
            trusted: false,
            autoprune: false,
            interactive_subagents: true,
            max_recursion: 2,
            steering: Steering::Terse,
            goal_skeptics: 2,
            self_verify: vec![
                SurfaceVerify::new(n, true),  // writes & edits: on (same model)
                SurfaceVerify::new(n, false), // commands: off
                SurfaceVerify::new(n, false), // monty: off
            ],
            tools: default_tools(),
            // Pre-seed the suggested default subagent; the user can keep, edit,
            // or remove it on the subagents screen.
            subagents: vec![default_subagent(catalog)],
        }
    }

    fn enabled_model_count(&self) -> usize {
        self.model_allowed.iter().filter(|&&on| on).count()
    }

    fn summarize(&self, catalog: &[AvailableModel]) -> AgentSummary {
        AgentSummary {
            lines: summary_lines(self, catalog),
        }
    }
}

/// Default model grant for a fresh agent/subagent: enable the first model and
/// make it the default; nothing selectable when the catalog is empty.
fn default_models(n: usize) -> (Vec<bool>, Option<usize>) {
    let mut allowed = vec![false; n];
    let default = if n > 0 {
        allowed[0] = true;
        Some(0)
    } else {
        None
    };
    (allowed, default)
}

/// Default tool grants: required always on; suggested on unless they need a
/// model (those wait for the user to choose one); everything else off.
fn default_tools() -> Vec<ToolState> {
    TOOLS
        .iter()
        .map(|tool| ToolState {
            grant: if matches!(tool.tier, Tier::Required)
                || (matches!(tool.tier, Tier::Suggested) && tool.requires_model.is_none())
            {
                ToolGrant::Enabled
            } else {
                ToolGrant::Disabled
            },
            model: None,
        })
        .collect()
}

/// The tools the suggested default subagent is granted on top of the always-on
/// required set (`read` / `write` / `shell`): search code, timers, background
/// commands, and delegation. Delegation still obeys recursion depth at runtime.
const RUNNER_TOOL_IDS: &[&str] = &["search", "timer", "background", "task"];

/// The suggested default subagent: an untrusted general "runner" that can
/// read/edit code, search, run commands, use timers and background commands,
/// and delegate to subagents (synchronously or in the background, when
/// recursion depth allows). Pre-seeded into every fresh [`AgentDraft`] so an
/// agent has a helper even when the user defines none of their own.
fn default_subagent(catalog: &[AvailableModel]) -> Subagent {
    let (model_allowed, default_model) = default_models(catalog.len());
    let tools = TOOLS
        .iter()
        .map(|tool| ToolState {
            grant: if matches!(tool.tier, Tier::Required) || RUNNER_TOOL_IDS.contains(&tool.id) {
                ToolGrant::Enabled
            } else {
                ToolGrant::Disabled
            },
            model: None,
        })
        .collect();
    Subagent {
        name: "runner".to_string(),
        trusted: false,
        model_allowed,
        default_model,
        tools,
    }
}

/// Human label for the default model, for summaries.
fn default_model_label(
    allowed: &[bool],
    default: Option<usize>,
    catalog: &[AvailableModel],
) -> String {
    match default.and_then(|i| catalog.get(i)) {
        Some(model) if allowed.get(default.unwrap()).copied().unwrap_or(false) => {
            model.label().to_string()
        }
        _ => "none".to_string(),
    }
}

fn count_enabled(states: &[ToolState]) -> usize {
    states
        .iter()
        .filter(|state| state.grant.is_enabled())
        .count()
}

fn summary_lines(draft: &AgentDraft, catalog: &[AvailableModel]) -> Vec<String> {
    let name = if draft.name.trim().is_empty() {
        "pilot".to_string()
    } else {
        draft.name.trim().to_string()
    };
    let trust = if draft.trusted {
        "trusted"
    } else {
        "untrusted (secrets & sealed values redacted)"
    };
    let skeptics = if draft.goal_skeptics == 0 {
        "off".to_string()
    } else {
        format!("{}", draft.goal_skeptics)
    };

    let mut lines = vec![
        format!("agent \u{201c}{name}\u{201d} \u{b7} {trust}"),
        format!(
            "  models: {}/{} enabled, default {}",
            draft.enabled_model_count(),
            catalog.len(),
            default_model_label(&draft.model_allowed, draft.default_model, catalog),
        ),
        format!(
            "  optimizations: auto-prune {}, interactive subagents {}, recursion depth {}, steering {}, goal skeptics {}",
            on_off(draft.autoprune),
            on_off(draft.interactive_subagents),
            draft.max_recursion,
            draft.steering.label(),
            skeptics,
        ),
        format!(
            "  self-verify: {} {} \u{b7} {} {} \u{b7} {} {}",
            SURFACES[0],
            draft.self_verify[0].describe(),
            SURFACES[1],
            draft.self_verify[1].describe(),
            SURFACES[2],
            draft.self_verify[2].describe(),
        ),
        {
            let granted: Vec<&str> = TOOLS
                .iter()
                .zip(&draft.tools)
                .filter(|(tool, state)| {
                    state.grant.is_enabled() || matches!(tool.tier, Tier::Required)
                })
                .map(|(tool, _)| tool.id)
                .collect();
            format!("  tools ({}): {}", granted.len(), granted.join(", "))
        },
    ];
    if draft.subagents.is_empty() {
        lines.push("  subagents: none".to_string());
    } else {
        for sub in &draft.subagents {
            let sub_name = if sub.name.trim().is_empty() {
                "unnamed".to_string()
            } else {
                sub.name.trim().to_string()
            };
            lines.push(format!(
                "  subagent \u{201c}{}\u{201d} \u{b7} {} \u{b7} {} model(s) \u{b7} {} tool(s)",
                sub_name,
                if sub.trusted { "trusted" } else { "untrusted" },
                sub.model_allowed.iter().filter(|&&on| on).count(),
                count_enabled(&sub.tools),
            ));
        }
    }
    lines
}

fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

/// Pick the singular or plural word for a count.
pub(super) fn plural(n: u32, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 { one } else { many }
}

/// What onboarding echoes about the created agent after the alt-screen closes.
pub(super) struct AgentSummary {
    lines: Vec<String>,
}

impl AgentSummary {
    pub(super) fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// Run the "create your first agent" wizard over `catalog` (the models
/// gathered from every provider onboarding added).
pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    catalog: &[AvailableModel],
) -> Result<Outcome> {
    let mut draft = AgentDraft::new(catalog);
    const LAST_PHASE: usize = 6;
    let mut phase = 0usize;
    loop {
        let nav = match phase {
            0 => basics::run(terminal, &mut draft)?,
            1 => models::run(
                terminal,
                catalog,
                &mut draft.model_allowed,
                &mut draft.default_model,
                "Choose the agent's models",
                "Tick every model this agent may use. Star one as the default.",
            )?,
            2 => trust::run(terminal, &mut draft)?,
            3 => optimizations::run(terminal, &mut draft, catalog)?,
            4 => tools::run(
                terminal,
                catalog,
                &mut draft.tools,
                "Grant tools",
                "Required tools are always on. Toggle the rest.",
            )?,
            5 => subagents::run(terminal, &mut draft, catalog)?,
            6 => review::run(terminal, &draft, catalog)?,
            _ => unreachable!("phase out of range"),
        };
        match nav {
            Nav::Next => {
                if phase == LAST_PHASE {
                    return Ok(Outcome::Created(draft.summarize(catalog)));
                }
                phase += 1;
            }
            Nav::Back => {
                if phase == 0 {
                    return Ok(Outcome::Back);
                }
                phase -= 1;
            }
            Nav::Quit => return Ok(Outcome::Quit),
        }
    }
}

#[cfg(test)]
pub(super) fn sample_catalog() -> Vec<AvailableModel> {
    vec![
        AvailableModel {
            provider_id: "openai",
            provider_display: "OpenAI Platform API",
            model_id: "gpt-5".to_string(),
            display: Some("GPT-5".to_string()),
        },
        AvailableModel {
            provider_id: "openai",
            provider_display: "OpenAI Platform API",
            model_id: "gpt-5-mini".to_string(),
            display: None,
        },
        AvailableModel {
            provider_id: "anthropic",
            provider_display: "Anthropic (Claude API)",
            model_id: "claude-4".to_string(),
            display: Some("Claude 4".to_string()),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_draft_has_the_requested_defaults() {
        let catalog = sample_catalog();
        let draft = AgentDraft::new(&catalog);
        // First model enabled and default.
        assert_eq!(draft.enabled_model_count(), 1);
        assert_eq!(draft.default_model, Some(0));
        // Trust and optimization defaults.
        assert!(!draft.trusted, "agents start untrusted");
        assert!(!draft.autoprune, "auto-prune starts off");
        assert!(
            draft.interactive_subagents,
            "interactive subagents start on"
        );
        assert_eq!(draft.steering, Steering::Terse);
        // Self-verify: writes on (same model), the rest off.
        assert!(!draft.self_verify[0].is_off());
        assert_eq!(draft.self_verify[0].same_copies, 1);
        assert!(draft.self_verify[1].is_off());
        assert!(draft.self_verify[2].is_off());
    }

    #[test]
    fn default_tool_grants_follow_tier_and_model_gating() {
        let draft = AgentDraft::new(&sample_catalog());
        for (state, tool) in draft.tools.iter().zip(TOOLS) {
            match tool.tier {
                Tier::Required => assert!(state.grant.is_enabled(), "{} should be on", tool.id),
                Tier::Suggested if tool.requires_model.is_none() => {
                    assert!(state.grant.is_enabled(), "{} should be on", tool.id)
                }
                // Model-gated suggested tools wait for a model.
                Tier::Suggested => {
                    assert!(!state.grant.is_enabled(), "{} needs a model first", tool.id)
                }
                Tier::Other => assert!(!state.grant.is_enabled(), "{} should be off", tool.id),
            }
        }
        // computer_use specifically must be off.
        let cu = TOOLS.iter().position(|t| t.id == "computer_use").unwrap();
        assert!(!draft.tools[cu].grant.is_enabled());
    }

    #[test]
    fn summary_reads_back_the_key_decisions() {
        let catalog = sample_catalog();
        let mut draft = AgentDraft::new(&catalog);
        draft.name = "navigator".to_string();
        draft.trusted = true;
        let summary = draft.summarize(&catalog);
        let joined = summary.lines().join("\n");
        assert!(joined.contains("navigator"), "{joined}");
        assert!(joined.contains("trusted"), "{joined}");
        assert!(joined.contains("default GPT-5"), "{joined}");
        // The suggested default subagent is pre-seeded, so it reads back here.
        assert!(
            joined.contains("subagent \u{201c}runner\u{201d}"),
            "{joined}"
        );
    }

    #[test]
    fn fresh_draft_pre_seeds_the_default_runner_subagent() {
        let catalog = sample_catalog();
        let draft = AgentDraft::new(&catalog);
        assert_eq!(
            draft.subagents.len(),
            1,
            "one suggested subagent by default"
        );
        let runner = &draft.subagents[0];
        assert_eq!(runner.name, "runner");
        assert!(!runner.trusted, "the default runner is untrusted");
        // Granted: the required set plus search, timer, background, task.
        let granted: std::collections::HashSet<&str> = TOOLS
            .iter()
            .zip(&runner.tools)
            .filter(|(tool, state)| state.grant.is_enabled() || matches!(tool.tier, Tier::Required))
            .map(|(tool, _)| tool.id)
            .collect();
        for id in [
            "read",
            "write",
            "shell",
            "search",
            "timer",
            "background",
            "task",
        ] {
            assert!(
                granted.contains(id),
                "runner should grant {id}: {granted:?}"
            );
        }
        // Not granted: powerful / unrelated tools stay off.
        for id in [
            "fetch",
            "websearch",
            "question",
            "lsp",
            "escalate",
            "computer_use",
        ] {
            assert!(
                !granted.contains(id),
                "runner should not grant {id}: {granted:?}"
            );
        }
    }
}
