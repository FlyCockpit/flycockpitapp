use super::*;

#[derive(Clone, Copy)]
pub(super) struct SlashCommand {
    pub(super) name: &'static str,
    pub(super) description: &'static str,
    pub(super) takes_args: bool,
    run: fn(&mut App, &str) -> bool,
    available: fn(&App) -> bool,
    describe: fn(&App, &SlashCommand) -> String,
}

/// A discovered skill surfaced as a slash-menu entry + bare-`/<name>` sugar
/// (implementation note). Owned (not `&'static`) because
/// the set is discovered at runtime, unlike the compile-time [`SlashCommand`]
/// registry.
#[derive(Clone, Debug)]
pub(super) struct SkillCommand {
    pub(super) name: String,
    pub(super) description: String,
}

/// A slash-menu entry: either a compile-time builtin or a discovered skill's
/// bare-`/<name>` sugar. The menu renders + dispatches over the union; a
/// builtin always shadows a same-named skill (the skill stays reachable via
/// `/skill <name>`).
#[derive(Clone, Copy)]
pub(super) enum SlashEntry<'a> {
    Builtin(&'a SlashCommand),
    Skill(&'a SkillCommand),
}

impl<'a> SlashEntry<'a> {
    pub(super) fn name(&self) -> &str {
        match self {
            SlashEntry::Builtin(c) => c.name,
            SlashEntry::Skill(s) => &s.name,
        }
    }

    /// The menu description, resolved against live [`App`] state. Toggle/
    /// cycle builtins reflect their current state; skill entries use their
    /// discovered descriptions.
    pub(super) fn description(&self, app: &App) -> String {
        match self {
            SlashEntry::Builtin(c) => app.slash_description_for(c),
            SlashEntry::Skill(s) => s.description.clone(),
        }
    }

    /// The text `Tab` completes the composer to. Builtins reuse their
    /// arg-aware completion; a bare skill entry completes to `/<name> ` with
    /// a trailing space so the user can append an optional task.
    pub(super) fn completion_text(&self) -> String {
        match self {
            SlashEntry::Builtin(c) => c.completion_text(),
            SlashEntry::Skill(s) => format!("/{} ", s.name),
        }
    }
}

#[derive(Clone)]
pub(super) struct SlashMenuCache {
    pub(super) builtins: Vec<&'static SlashCommand>,
    descriptions: Vec<(&'static str, String)>,
}

impl SlashMenuCache {
    pub(super) fn build(app: &App) -> Self {
        let builtins: Vec<&'static SlashCommand> = SLASH_COMMANDS
            .iter()
            .filter(|command| command.is_available(app))
            .collect();
        let descriptions = builtins
            .iter()
            .map(|command| (command.name, command.rendered_description(app)))
            .collect();
        Self {
            builtins,
            descriptions,
        }
    }

    pub(super) fn description_for(&self, command: &SlashCommand) -> Option<&str> {
        self.descriptions
            .iter()
            .find_map(|(name, description)| (*name == command.name).then_some(description.as_str()))
    }
}

impl SlashCommand {
    pub(super) fn is_available(&self, app: &App) -> bool {
        (self.available)(app)
    }

    fn rendered_description(&self, app: &App) -> String {
        (self.describe)(app, self)
    }

    pub(super) fn completion_text(&self) -> String {
        if self.takes_args {
            format!("/{} ", self.name)
        } else {
            format!("/{}", self.name)
        }
    }
}

fn available_always(_: &App) -> bool {
    true
}

fn available_editor(_: &App) -> bool {
    std::env::var_os("EDITOR").is_some()
}

fn available_lazygit(_: &App) -> bool {
    program_on_path("lazygit")
}

fn describe_static(_: &App, command: &SlashCommand) -> String {
    command.description.to_string()
}

fn describe_preflight(app: &App, _: &SlashCommand) -> String {
    format!(
        "{} Rewrite your prompt via the utility model before sending (arg: on/off; bare = toggle)",
        on_off(app.preflight_enabled)
    )
}

fn describe_longcache(app: &App, _: &SlashCommand) -> String {
    format!(
        "{} Keep prompt-cache prefixes under extended retention for this session (arg: on/off; bare = toggle)",
        on_off(app.longcache_enabled)
    )
}

fn describe_sandbox_escalate(app: &App, _: &SlashCommand) -> String {
    format!(
        "{} Allow explicit sandbox-escalation retries for this session (arg: allow/disallow; bare = status)",
        on_off(app.sandbox_escalation_enabled)
    )
}

fn describe_toggle_redaction(app: &App, _: &SlashCommand) -> String {
    format!(
        "Toggle secret redaction sources for this session (env {}, file {}, ssh {}) (arg: env/file/ssh; bare opens a picker)",
        on_off(app.redact_scan_environment),
        on_off(app.redact_scan_dotenv),
        on_off(app.redact_scan_ssh_keys),
    )
}

fn describe_caffeinate(app: &App, _: &SlashCommand) -> String {
    format!(
        "{} Keep the machine awake so agents survive a closed lid (arg: on/off/until-idle)",
        on_off(app.caffeinate_active)
    )
}

fn describe_sandbox(app: &App, _: &SlashCommand) -> String {
    let mut desc = format!(
        "Sandbox mode is `{}` (arg: off/on/container/container-readonly; bare cycles)",
        sandbox_mode_label(app.sandbox_mode)
    );
    if app.sandbox_mode.is_container() {
        desc.push_str(if app.container_network_enabled {
            "; network on"
        } else {
            "; network off"
        });
    }
    desc
}

fn describe_mouse(app: &App, _: &SlashCommand) -> String {
    format!(
        "{} Toggle mouse capture (click-to-position, drag-select) on/off",
        on_off(app.mouse_capture)
    )
}

fn describe_tool_calls(app: &App, _: &SlashCommand) -> String {
    format!(
        "{} Hide model tool-call rows in this main assistant view (arg: hide/show; bare = toggle)",
        on_off(app.hide_tool_calls)
    )
}

fn describe_mcp(app: &App, _: &SlashCommand) -> String {
    let Some(cfg) = app.mcp_snapshot() else {
        return "Manage MCP servers (status unavailable) (arg: settings/list/on/off/toggle [id]; \
                bare = list)"
            .to_string();
    };
    let enabled = cfg.servers.values().filter(|s| s.enabled).count();
    let total = cfg.servers.len();
    format!(
        "Manage MCP servers ({enabled}/{total} enabled) (arg: settings/list/on/off/toggle [id]; bare = list)"
    )
}

fn on_off(on: bool) -> &'static str {
    if on { "(on)" } else { "(off)" }
}

pub(super) const SLASH_COMMANDS: &[SlashCommand] = &[
    SlashCommand {
        name: "caffeinate",
        description: "Keep the machine awake so agents survive a closed lid (arg: on/off/until-idle)",
        takes_args: true,
        run: run_caffeinate,
        available: available_always,
        describe: describe_caffeinate,
    },
    SlashCommand {
        name: "agent",
        description: "Switch the primary agent (arg: name; bare lists the chat-owning agents)",
        takes_args: true,
        run: run_agent,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "assistant",
        description: "Open or create the latest session for a persistent assistant",
        takes_args: true,
        run: run_assistant,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "build",
        description: "Switch the primary agent to Build (make changes)",
        takes_args: false,
        run: run_build,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "btw",
        description: "Open a persistent side conversation pane (arg: question/new/tangent/end)",
        takes_args: true,
        run: run_btw,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "clear",
        description: "Clear the chat and start a fresh session (alias of /new)",
        takes_args: false,
        run: run_new_session,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "compact",
        description: "Compress the conversation to save context",
        takes_args: false,
        run: run_compact,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "config",
        description: "Open the settings dialog (alias of /settings)",
        takes_args: false,
        run: run_settings,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "context",
        description: "Show a colored breakdown of how the context window is filled",
        takes_args: false,
        run: run_context,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "copy",
        description: "Copy the last response to the clipboard (arg: markdown/plain/rich)",
        takes_args: true,
        run: run_copy,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "copy-pick",
        description: "Pick any message or code block to copy",
        takes_args: false,
        run: run_copy_pick,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "curator",
        description: "Manage skill curation (arg: status/run/pin/unpin/restore/rollback)",
        takes_args: true,
        run: run_curator,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "diff",
        description: "Browse a read-only diff pane (arg: worktree/staged/last; bare = worktree)",
        takes_args: true,
        run: run_diff,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "doctor",
        description: "Show a compact Cockpit diagnostics snapshot",
        takes_args: false,
        run: run_doctor,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "editor",
        description: "Open $EDITOR in an embedded pane (arg: left/right/top/bottom)",
        takes_args: true,
        run: run_editor,
        available: available_editor,
        describe: describe_static,
    },
    SlashCommand {
        name: "exit",
        description: "Quit cockpit",
        takes_args: false,
        run: run_exit,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "export",
        description: "Export the current conversation to .cockpit/exports/ (arg: debug for the full bundle)",
        takes_args: true,
        run: run_export,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "favorite",
        description: "Mark the active model as a favorite",
        takes_args: false,
        run: run_favorite,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "fetch-models",
        description: "Refresh provider model catalogs from configured providers",
        takes_args: false,
        run: run_fetch_models,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "fork",
        description: "Branch a new conversation from the current point",
        takes_args: false,
        run: run_fork,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "git",
        description: "Run a git command and share its output with the agent",
        takes_args: false,
        run: run_git,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "gitignore-allow",
        description: "Manage the project's gitignore read-allowlist (arg: path-or-glob to add; bare opens settings)",
        takes_args: true,
        run: run_gitignore_allow,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "goal",
        description: "Create or manage a persisted session goal (arg: objective/status/pause/resume/clear/edit)",
        takes_args: true,
        run: run_goal,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "guidance",
        description: "Review pending computer-use guidance proposals (Owner only)",
        takes_args: false,
        run: run_guidance,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "goal-settings",
        description: "Edit goal-verification overrides for this session or agent",
        takes_args: false,
        run: run_goal_settings,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "help",
        description: "Open getting-started help and the slash command reference",
        takes_args: false,
        run: run_help,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "init",
        description: "Explore the project and write its instructions file (arg: target path)",
        takes_args: true,
        run: run_init,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "schedule",
        description: "List active scheduled tasks (arg: cancel <id> to cancel one)",
        takes_args: true,
        run: run_schedule,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "keys",
        description: "Open the which-key overlay of context-aware keybindings (also Ctrl+K)",
        takes_args: false,
        run: run_keys,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "lazygit",
        description: "Open lazygit in an embedded pane",
        takes_args: false,
        run: run_lazygit,
        available: available_lazygit,
        describe: describe_static,
    },
    SlashCommand {
        name: "learn",
        description: "Turn paths, URLs, text, or the recent workflow into a reusable skill",
        takes_args: true,
        run: run_learn,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "mcp",
        description: "Manage MCP servers (arg: settings/list/on/off/toggle [id]; bare = list)",
        takes_args: true,
        run: run_mcp,
        available: available_always,
        describe: describe_mcp,
    },
    SlashCommand {
        name: "model",
        description: "Switch this session's model (Ctrl+Enter also sets the default for new sessions)",
        takes_args: false,
        run: run_model,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "multireview",
        description: "Run a parallel multi-model, multi-harness read-only code review",
        takes_args: false,
        run: run_multireview,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "model-comparison",
        description: "Shadow every request to tandem models for comparison (session-only; opens a picker)",
        takes_args: false,
        run: run_model_comparison,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "model-settings",
        description: "Open the active model's context, cache, shrink, and mode settings",
        takes_args: false,
        run: run_model_settings,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "longcache",
        description: "Toggle extended prompt-cache retention for this session",
        takes_args: true,
        run: run_longcache,
        available: available_always,
        describe: describe_longcache,
    },
    SlashCommand {
        name: "mouse",
        description: "Toggle mouse capture (click-to-position, drag-select) on/off",
        takes_args: false,
        run: run_mouse,
        available: available_always,
        describe: describe_mouse,
    },
    SlashCommand {
        name: "new",
        description: "Clear the chat and start a fresh session",
        takes_args: false,
        run: run_new_session,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "note",
        description: "Append a session-history note to self; never sent to the model (arg: text)",
        takes_args: true,
        run: run_note,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "scratchpad",
        description: "Open the project scratchpad (editable markdown notes; also Ctrl+N)",
        takes_args: false,
        run: run_scratchpad,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "leaks",
        description: "List, rotate, or delete contained leak reports machine-wide",
        takes_args: true,
        run: run_leaks,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "sealed",
        description: "Manage sealed Owner values: list, create/rotate/replace (no-echo), recover, edit, action",
        takes_args: true,
        run: run_sealed,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "permissions",
        description: "View and delete persisted command/path approvals across project and global scopes",
        takes_args: false,
        run: run_permissions,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "tools",
        description: "Edit the current agent's tool surface",
        takes_args: false,
        run: run_tools,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "tool-calls",
        description: "Hide model tool-call rows in this main assistant view (arg: hide/show; bare = toggle)",
        takes_args: true,
        run: run_tool_calls,
        available: available_always,
        describe: describe_tool_calls,
    },
    SlashCommand {
        name: "pin",
        description: "Pick a message to pin (↑/↓ move, enter pin, esc cancel)",
        takes_args: false,
        run: run_pin,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "pins",
        description: "Review pinned messages (↑/↓ jump, d/✓ unpin, esc close)",
        takes_args: false,
        run: run_pins,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "pin-context",
        description: "Pin verbatim text so it survives /compact (arg: text)",
        takes_args: true,
        run: run_pin_context,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "preflight",
        description: "Rewrite your prompt via the utility model before sending (arg: on/off; bare = toggle)",
        takes_args: true,
        run: run_preflight,
        available: available_always,
        describe: describe_preflight,
    },
    SlashCommand {
        name: "quick",
        description: "Open session quick settings",
        takes_args: false,
        run: run_quick,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "resources",
        description: "Show resource scheduler state (arg: promote <display-id-or-uuid>)",
        takes_args: true,
        run: run_resources,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "plan",
        description: "Switch the primary agent to Plan (author a plan)",
        takes_args: false,
        run: run_plan,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "prune",
        description: "Collapse superseded snapshot reads to reclaim context",
        takes_args: false,
        run: run_prune,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "ps",
        description: "List this session's running async jobs",
        takes_args: false,
        run: run_ps,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "rename",
        description: "Rename the current session (arg: title)",
        takes_args: true,
        run: run_rename,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "resume",
        description: "Browse and resume previous sessions (alias of /sessions)",
        takes_args: false,
        run: run_sessions,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "sandbox",
        description: "Set sandbox mode (arg: off/on/container/container-readonly; bare cycles)",
        takes_args: true,
        run: run_sandbox,
        available: available_always,
        describe: describe_sandbox,
    },
    SlashCommand {
        name: "sandbox-escalate",
        description: "Allow explicit sandbox escalation (arg: allow/disallow; bare = status)",
        takes_args: true,
        run: run_sandbox_escalate,
        available: available_always,
        describe: describe_sandbox_escalate,
    },
    SlashCommand {
        name: "sessions",
        description: "Browse and resume previous sessions",
        takes_args: false,
        run: run_sessions,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "settings",
        description: "Open the settings dialog (includes the default model for new sessions)",
        takes_args: false,
        run: run_settings,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "setup",
        description: "Open setup wizards (arg: wizard id; bare lists registered wizards)",
        takes_args: true,
        run: run_setup,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "side",
        description: "Start a throwaway side conversation forked from here (`/side end` to discard)",
        takes_args: false,
        run: run_side,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "skill",
        description: "Invoke a discovered skill by name (arg: skill-name [task]; bare lists skills)",
        takes_args: true,
        run: run_skill,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "skills",
        description: "List every discovered skill in a read-only overlay",
        takes_args: false,
        run: run_skills,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "stats",
        description: "On-device model and project performance (tokens, recovery, languages)",
        takes_args: false,
        run: run_stats,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "session-setup",
        description: "Session setup panel: agent, model, tools, and MCPs for this session",
        takes_args: false,
        run: run_session_setup,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "tree",
        description: "Agent tree: breadcrumbs, child focus, and the ordered attention list",
        takes_args: false,
        run: run_agent_tree,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "usage",
        description: "Show vendor plan limits and quota per provider (arg: provider-id; bare = all)",
        takes_args: true,
        run: run_usage,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "stop",
        description: "Stop this session's async jobs (arg: job-id for one, bare for all)",
        takes_args: true,
        run: run_stop,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "toggle-redaction",
        description: "Toggle secret redaction sources for this session (arg: env/file/ssh; bare opens a picker)",
        takes_args: true,
        run: run_toggle_redaction,
        available: available_always,
        describe: describe_toggle_redaction,
    },
    SlashCommand {
        name: "version",
        description: "Show the cockpit version and OS/platform info",
        takes_args: false,
        run: run_version,
        available: available_always,
        describe: describe_static,
    },
];

struct HiddenSlashAlias {
    alias: &'static str,
    canonical: &'static str,
}

const HIDDEN_SLASH_ALIASES: &[HiddenSlashAlias] = &[
    HiddenSlashAlias {
        alias: "?",
        canonical: "help",
    },
    HiddenSlashAlias {
        alias: "modelsettings",
        canonical: "model-settings",
    },
    HiddenSlashAlias {
        alias: "toggle-redact",
        canonical: "toggle-redaction",
    },
    HiddenSlashAlias {
        alias: "notes",
        canonical: "scratchpad",
    },
    HiddenSlashAlias {
        alias: "keybindings",
        canonical: "keys",
    },
];

fn slash_command_by_name(name: &str) -> Option<&'static SlashCommand> {
    SLASH_COMMANDS.iter().find(|c| c.name == name)
}

pub(super) fn hidden_slash_alias(query: &str) -> Option<SlashCommand> {
    let canonical = HIDDEN_SLASH_ALIASES
        .iter()
        .find(|alias| alias.alias == query)?
        .canonical;
    slash_command_by_name(canonical).copied()
}

fn run_exit(app: &mut App, _: &str) -> bool {
    app.request_guarded_exit()
}

fn run_editor(app: &mut App, args: &str) -> bool {
    app.open_editor(parse_pane_side(args));
    false
}

fn run_lazygit(app: &mut App, _: &str) -> bool {
    app.open_lazygit();
    false
}

fn run_git(app: &mut App, args: &str) -> bool {
    app.run_git_command(args);
    false
}

fn run_settings(app: &mut App, _: &str) -> bool {
    app.dialog = Dialog::open(&app.launch.cwd);
    app.dialog
        .apply_host_capabilities(app.host_capabilities.clone(), app.agent_runner.is_some());
    false
}

fn run_setup(app: &mut App, args: &str) -> bool {
    let wizard_id = args.trim();
    if wizard_id.is_empty() {
        app.dialog = Dialog::open_setup(&app.launch.cwd);
        return false;
    }
    let dialog = if wizard_id == cockpit_core::wizard::MODEL_WIZARD_ID {
        Ok(Dialog::open_model_setup_choice(
            &app.launch.cwd,
            if app.pending_model_selection.is_none() {
                app.launch.active_model.clone()
            } else {
                None
            },
            app.pending_model_selection.as_ref().map(|pending| {
                (
                    pending.requested.provider.clone(),
                    pending.requested.model.clone(),
                )
            }),
        ))
    } else {
        Dialog::open_setup_wizard(&app.launch.cwd, wizard_id)
    };
    match dialog {
        Ok(dialog) => app.dialog = dialog,
        Err(error) => app.push_plain(format!("/setup: {error}")),
    }
    false
}

fn run_gitignore_allow(app: &mut App, args: &str) -> bool {
    let glob = (!args.trim().is_empty()).then_some(args.trim());
    app.dialog = Dialog::open_gitignore_allow(&app.launch.cwd, glob);
    false
}

fn run_goal(app: &mut App, args: &str) -> bool {
    app.handle_goal_command(args);
    false
}

fn run_guidance(app: &mut App, _: &str) -> bool {
    let attached = app
        .agent_runner
        .as_ref()
        .and_then(|runner| runner.as_ref().ok())
        .map(|runner| runner.attached_request_binding());
    app.overlay = Overlay::GuidanceReview(crate::tui::guidance_review::GuidanceReviewPane::open(
        attached,
        app.async_actions.notifier(),
    ));
    false
}

fn run_mcp(app: &mut App, args: &str) -> bool {
    app.handle_mcp_command(args);
    false
}

fn run_model_settings(app: &mut App, _: &str) -> bool {
    app.dialog = Dialog::open_model_settings(&app.launch.cwd);
    false
}

fn run_fetch_models(app: &mut App, _: &str) -> bool {
    app.spawn_fetch_models();
    false
}

fn run_model(app: &mut App, _: &str) -> bool {
    app.open_model_picker();
    false
}

fn run_multireview(app: &mut App, _: &str) -> bool {
    match crate::tui::multireview_dialog::MultireviewDialog::open(
        &app.launch.cwd,
        &app.config_snapshot.extended,
        &app.inventory_models(),
        &app.usage_models,
    ) {
        Ok(dialog) => app.overlay = Overlay::Multireview(dialog),
        Err(e) => app.history.push(HistoryEntry::Plain {
            line: format!("/multireview: {e}"),
        }),
    }
    false
}

fn run_model_comparison(app: &mut App, _: &str) -> bool {
    app.open_model_comparison_dialog();
    false
}

fn run_favorite(app: &mut App, _: &str) -> bool {
    let Some(active) = app.active_model_selection.clone() else {
        app.history.push(HistoryEntry::Plain {
            line: "/favorite: no active model — run /model first".to_string(),
        });
        return false;
    };
    let Some(provider) = app
        .config_snapshot
        .providers
        .providers
        .get(&active.provider)
    else {
        app.push_plain(format!(
            "/favorite: active provider {} is no longer configured",
            active.provider
        ));
        return false;
    };
    let Some(model) = provider
        .models
        .iter()
        .find(|model| model.id == active.model)
    else {
        app.push_plain(format!(
            "/favorite: active model {} is no longer configured for provider {}",
            active.model, active.provider
        ));
        return false;
    };
    let favorite = !model.favorite;
    app.send_daemon_request(
        "/favorite",
        cockpit_proto::Request::SetModelFavorite {
            provider: active.provider.clone(),
            model: active.model.clone(),
            favorite,
        },
        super::ControlApplied::ModelFavorite {
            provider: active.provider,
            model: active.model,
            favorite,
        },
    );
    false
}

fn run_new_session(app: &mut App, _: &str) -> bool {
    app.pending_new_session = true;
    false
}

fn run_mouse(app: &mut App, _: &str) -> bool {
    app.toggle_mouse_capture_inline();
    false
}

fn run_init(app: &mut App, args: &str) -> bool {
    app.handle_init_command(args);
    false
}

fn run_learn(app: &mut App, args: &str) -> bool {
    app.handle_learn_command(args);
    false
}

fn run_schedule(app: &mut App, args: &str) -> bool {
    app.handle_schedule_command(args);
    false
}

fn run_ps(app: &mut App, _: &str) -> bool {
    app.handle_ps_command();
    false
}

fn run_stop(app: &mut App, args: &str) -> bool {
    app.handle_stop_command(args);
    false
}

fn run_caffeinate(app: &mut App, args: &str) -> bool {
    app.handle_caffeinate_command(args);
    false
}

fn run_compact(app: &mut App, args: &str) -> bool {
    if !args.trim().is_empty() {
        app.history.push(HistoryEntry::Plain {
            line: "/compact: usage `/compact`".to_string(),
        });
    } else {
        app.start_compact();
    }
    false
}

fn run_copy(app: &mut App, args: &str) -> bool {
    app.handle_copy_command(args);
    false
}

fn run_copy_pick(app: &mut App, _: &str) -> bool {
    app.enter_copy_pick_mode();
    false
}

fn run_prune(app: &mut App, _: &str) -> bool {
    app.arm_prune_confirm();
    false
}

fn run_pin_context(app: &mut App, args: &str) -> bool {
    app.handle_pin_context_command(args);
    false
}

fn run_pin(app: &mut App, _: &str) -> bool {
    app.enter_pin_pick_mode();
    false
}

fn run_pins(app: &mut App, _: &str) -> bool {
    app.enter_pins_review_mode();
    false
}

fn run_keys(app: &mut App, _: &str) -> bool {
    app.toggle_keys_overlay();
    false
}

fn run_help(app: &mut App, _: &str) -> bool {
    app.overlay = Overlay::Help(super::help_overlay::HelpOverlay::open());
    false
}

fn run_sandbox(app: &mut App, args: &str) -> bool {
    app.handle_sandbox_command(args);
    false
}

fn run_sandbox_escalate(app: &mut App, args: &str) -> bool {
    app.handle_sandbox_escalate_command(args);
    false
}

fn run_doctor(app: &mut App, _: &str) -> bool {
    app.handle_doctor_command();
    false
}

fn run_toggle_redaction(app: &mut App, args: &str) -> bool {
    app.handle_toggle_redaction_command(args);
    false
}

fn run_preflight(app: &mut App, args: &str) -> bool {
    app.handle_preflight_command(args);
    false
}

fn run_longcache(app: &mut App, args: &str) -> bool {
    app.handle_longcache_command(args);
    false
}

fn run_quick(app: &mut App, _: &str) -> bool {
    app.open_quick_dialog();
    false
}

fn run_stats(app: &mut App, _: &str) -> bool {
    let worktree_root = app.resolved_worktree_root();
    let mut pane =
        crate::tui::stats_pane::StatsPane::open(worktree_root.as_deref(), &app.launch.cwd);
    let fetch = pane.take_pending_fetch_key();
    app.overlay = Overlay::Stats(pane);
    if let Some(key) = fetch {
        app.start_stats_rollup_action(key);
    }
    false
}

fn run_session_setup(app: &mut App, _: &str) -> bool {
    app.open_session_setup();
    false
}

fn run_agent_tree(app: &mut App, _: &str) -> bool {
    app.open_agent_tree();
    false
}

fn run_usage(app: &mut App, args: &str) -> bool {
    app.start_provider_usage_action(args.to_string());
    false
}

fn run_context(app: &mut App, _: &str) -> bool {
    let snapshot = app.context_snapshot();
    app.overlay = Overlay::Context(crate::tui::context_pane::ContextPane::open(snapshot));
    false
}

fn run_diff(app: &mut App, args: &str) -> bool {
    let source = crate::tui::diff_pane::parse_source_arg(args);
    let mut pane = crate::tui::diff_pane::DiffPane::open(
        source,
        &app.launch.cwd,
        &app.history,
        app.diff_style,
    );
    let fetch = pane.take_pending_fetch();
    app.overlay = Overlay::Diff(pane);
    if let Some((operation_id, source)) = fetch {
        app.start_git_diff_action(operation_id, source);
    }
    false
}

fn run_sessions(app: &mut App, _: &str) -> bool {
    let daemon_socket = app
        .sessions_daemon_socket()
        .map(std::path::Path::to_path_buf);
    let worktree_root = app.resolved_worktree_root();
    app.overlay = Overlay::Sessions(crate::tui::sessions_pane::SessionsPane::open(
        worktree_root.as_deref(),
        &app.launch.cwd,
        app.daemon_connected,
        daemon_socket,
        app.config_snapshot.extended.tui.use_emojis,
    ));
    if app.daemon_connected {
        app.start_sessions_list_action();
    }
    false
}

fn run_skill(app: &mut App, args: &str) -> bool {
    app.handle_skill_command(args);
    false
}

fn run_curator(app: &mut App, args: &str) -> bool {
    app.handle_curator_command(args);
    false
}

fn run_skills(app: &mut App, _: &str) -> bool {
    app.open_skills_pane();
    false
}

fn run_scratchpad(app: &mut App, _: &str) -> bool {
    app.open_scratchpad_pane();
    false
}

fn run_note(app: &mut App, args: &str) -> bool {
    app.handle_note_command(args);
    false
}

fn run_leaks(app: &mut App, args: &str) -> bool {
    app.handle_leaks_command(args);
    false
}

fn run_sealed(app: &mut App, args: &str) -> bool {
    app.handle_sealed_command(args);
    false
}

/// Parse `/leaks` arguments into the metadata-only Owner RPC to send, or `None`
/// (usage) for anything unrecognized. Recognizes exactly the subcommands in the
/// usage string: bare/`list`, `rotate <id> <accept|dismiss|rotated>`, and
/// `delete <id>`. No `reveal` subcommand is parsed here.
fn leaks_request(args: &str) -> Option<cockpit_proto::Request> {
    use cockpit_proto::{LeakRotationDisposition, Request};
    let args = args.trim();
    if args.is_empty() || args == "list" {
        return Some(Request::ListLeakReports {
            cursor: None,
            limit: None,
            project_root: None,
            session_id: None,
            rotation: None,
        });
    }
    let mut tokens = args.split_whitespace();
    match tokens.next() {
        Some("rotate") => {
            let report_id = tokens.next()?.to_string();
            let rotation = match tokens.next()? {
                "accept" => LeakRotationDisposition::Accept,
                "dismiss" => LeakRotationDisposition::Dismiss,
                "rotated" => LeakRotationDisposition::Rotated,
                _ => return None,
            };
            if tokens.next().is_some() {
                return None;
            }
            Some(Request::MarkLeakRotated {
                report_id,
                rotation,
            })
        }
        Some("delete") => {
            let report_id = tokens.next()?.to_string();
            if tokens.next().is_some() {
                return None;
            }
            Some(Request::DeleteLeakReport { report_id })
        }
        _ => None,
    }
}

/// Render a page of leak-report metadata as transcript text. Takes only
/// `&LeakReportsPage`, which cannot represent plaintext, ciphertext, prefix,
/// length, or fingerprint by construction; every rendered field is safe
/// metadata.
fn format_leak_reports(page: &cockpit_proto::LeakReportsPage) -> String {
    if page.reports.is_empty() {
        return "/leaks: no contained leak reports".to_string();
    }
    let mut out = String::from(
        "/leaks: report_id | source | category | status | rotation | rotation_plan | seen_count | last_reported_ms",
    );
    for report in &page.reports {
        let rotation_plan = match report.rotation_plan {
            Some(plan) => format!("{plan:?}"),
            None => "-".to_string(),
        };
        out.push('\n');
        out.push_str(&format!(
            "{} | {} | {} | {} | {} | {} | {} | {}",
            report.report_id,
            report.source,
            report.category,
            report.status,
            report.rotation,
            rotation_plan,
            report.seen_count,
            report.last_reported_ms,
        ));
    }
    if page.has_more {
        out.push_str("\n/leaks: more reports available; paging arrives with the LeaksPane");
    }
    out
}

/// Map a `/leaks` daemon result to transcript text. Follows the `/sealed`
/// shape; there is no `Response::Error` variant, and the unexpected-response
/// arm never renders the `Debug` of a daemon response.
fn leak_response_text(result: Result<cockpit_proto::Response, String>) -> String {
    use cockpit_proto::Response;
    match result {
        Ok(Response::LeakReports { page }) => format_leak_reports(&page),
        Ok(Response::LeakRotationUpdated {
            report_id,
            rotation,
        }) => {
            format!("/leaks: rotated {report_id} -> {rotation}")
        }
        Ok(Response::LeakReportDeleted { report_id }) => {
            format!("/leaks: deleted protected value for {report_id}; safe metadata retained")
        }
        Ok(_) => "/leaks: unexpected response".to_string(),
        Err(e) => format!("/leaks: {e}"),
    }
}

fn run_agent(app: &mut App, args: &str) -> bool {
    app.handle_agent_command(args);
    false
}

fn run_assistant(app: &mut App, args: &str) -> bool {
    app.handle_assistant_command(args);
    false
}

fn run_plan(app: &mut App, _: &str) -> bool {
    app.swap_primary_agent("Plan");
    false
}

fn run_build(app: &mut App, _: &str) -> bool {
    app.swap_primary_agent("Build");
    false
}

fn run_permissions(app: &mut App, _: &str) -> bool {
    let worktree_root = app.resolved_worktree_root();
    app.overlay = Overlay::Permissions(crate::tui::permissions_pane::PermissionsPane::open(
        worktree_root.as_deref(),
    ));
    false
}

fn run_tools(app: &mut App, _: &str) -> bool {
    let agent = app
        .agent_path
        .last()
        .cloned()
        .unwrap_or_else(|| app.launch.agent_name.clone());
    match crate::tui::tools_pane::ToolsPane::open(
        &app.launch.cwd,
        &agent,
        app.agent_path.len() == 1,
    ) {
        Ok(pane) => {
            app.overlay = Overlay::Tools(pane);
        }
        Err(error) => {
            app.push_plain(format!("/tools: {error:#}"));
        }
    }
    false
}

fn run_tool_calls(app: &mut App, args: &str) -> bool {
    app.handle_tool_calls_command(args);
    false
}

fn run_goal_settings(app: &mut App, _: &str) -> bool {
    let agent = app
        .agent_path
        .last()
        .cloned()
        .unwrap_or_else(|| app.launch.agent_name.clone());
    match crate::tui::goal_settings_pane::GoalSettingsPane::open(
        &app.launch.cwd,
        &agent,
        app.agent_path.len() == 1,
    ) {
        Ok(pane) => {
            app.overlay = Overlay::GoalSettings(pane);
        }
        Err(error) => {
            app.push_plain(format!("/goal-settings: {error:#}"));
        }
    }
    false
}

fn run_resources(app: &mut App, args: &str) -> bool {
    app.handle_resources_command(args);
    false
}

fn run_fork(app: &mut App, args: &str) -> bool {
    app.handle_fork_command(args);
    false
}

fn run_side(app: &mut App, args: &str) -> bool {
    app.handle_side_command(args);
    false
}

fn run_btw(app: &mut App, args: &str) -> bool {
    app.handle_btw_command(args);
    false
}

fn run_rename(app: &mut App, args: &str) -> bool {
    app.handle_rename_command(args);
    false
}

fn run_export(app: &mut App, args: &str) -> bool {
    app.handle_export_command(args);
    false
}

fn run_version(app: &mut App, _: &str) -> bool {
    app.handle_version_command();
    false
}

impl App {
    pub(super) fn execute_slash(&mut self, cmd: SlashCommand) -> bool {
        let raw = self.composer.text().to_string();
        self.clear_composer_buffer();
        self.reset_slash_window();
        self.record_usage(cockpit_proto::UsageKind::Slash, cmd.name.to_string(), None);
        let args = slash_args(&raw);
        (cmd.run)(self, &args)
    }

    pub(super) fn handle_resources_command(&mut self, args: &str) {
        let mut parts = args.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (None, _, _) => {
                self.overlay =
                    Overlay::Resources(crate::tui::resources_pane::ResourcesPane::open());
                self.start_resources_snapshot_action();
            }
            (Some("promote"), Some(request_id), None) => {
                self.start_resource_promote_token_action(request_id.to_string());
            }
            _ => {
                self.push_plain(
                    "/resources: usage `/resources` or `/resources promote <display-id-or-uuid>`"
                        .to_string(),
                );
            }
        }
    }

    /// `/init [path]`: explore the project and write its instructions
    /// file via the normal `Build` → `builder` (single-writer) delegation
    /// path. With no arg the target is the first configured guidance
    /// filename (`agent_guidance_files[0]`, default `AGENTS.md`); with an
    /// arg it's that path. When the target already exists, opens the
    /// update/overwrite/cancel prompt (reusing the question dialog) and
    /// honors the choice; otherwise dispatches the fresh-write turn
    /// immediately. `config.json` is never touched.
    pub(super) fn handle_init_command(&mut self, args: &str) {
        if self.busy {
            self.push_plain("/init: a turn is already running — wait for it to finish".to_string());
            return;
        }
        let explicit = {
            let a = args.trim();
            if a.is_empty() { None } else { Some(a) }
        };
        let target = cockpit_core::init::resolve_target(&self.launch.cwd, explicit);
        let display = cockpit_core::init::display_target(&self.launch.cwd, &target);

        if target.exists() {
            // Existing target: ask update / overwrite / cancel via the
            // shared question dialog, driven locally (no daemon interrupt).
            use cockpit_proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
            let interrupt_id = uuid::Uuid::new_v4();
            let set = InterruptQuestionSet {
                questions: vec![InterruptQuestion::Single {
                    prompt: format!("`{display}` already exists — how should /init proceed?"),
                    options: vec![
                        InterruptOption {
                            id: "update".into(),
                            label: "Update in place".into(),
                            description: Some(
                                "Revise and extend, preserving accurate content".into(),
                            ),
                            secondary: false,
                        },
                        InterruptOption {
                            id: "overwrite".into(),
                            label: "Overwrite from scratch".into(),
                            description: Some("Replace the file entirely".into()),
                            secondary: false,
                        },
                        InterruptOption {
                            id: "cancel".into(),
                            label: "Cancel".into(),
                            description: None,
                            secondary: false,
                        },
                    ],
                    allow_freetext: false,
                    command_detail: None,
                    // `/init` choice is an agent-asked question, not a
                    // tool-permission approval — keep radios.
                    permission: false,
                    approval_class: None,
                    sandbox_escalation: None,
                }],
            };
            let lockout = self.dialog_lockout();
            self.pending_local_choice = Some(LocalChoice::Init(PendingInit {
                interrupt_id,
                display,
            }));
            self.question_dialog = Some(
                crate::tui::dialog::question::QuestionDialog::new(
                    interrupt_id,
                    String::new(),
                    set,
                    lockout,
                )
                .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
            );
            return;
        }

        // Fresh file: dispatch the create turn straight away.
        let prompt =
            cockpit_core::init::build_init_prompt(&display, cockpit_core::init::InitMode::Create);
        self.dispatch_init_turn(&display, prompt);
    }

    pub(super) fn handle_learn_command(&mut self, args: &str) {
        if self.busy {
            self.push_plain(
                "/learn: a turn is already running — wait for it to finish".to_string(),
            );
            return;
        }
        let subject = cockpit_core::skills::subject_from_parts(&[args.to_string()]);
        let prompt = cockpit_core::skills::build_learn_prompt(&subject);
        self.pin_chat_to_tail();
        self.begin_working_span();
        self.dispatch_optimistic_user_submission(
            if args.trim().is_empty() {
                "/learn".to_string()
            } else {
                format!("/learn {}", args.trim())
            },
            ClientUserSubmission {
                origin: cockpit_client::submission::SubmissionOrigin::ExternalRoot,
                ..ClientUserSubmission::text(prompt)
            },
            "/learn",
            true,
            &[],
        );
    }

    pub(super) fn handle_curator_command(&mut self, args: &str) {
        let Some(endpoint) = self.attached_daemon_endpoint() else {
            self.push_plain(
                "/curator: Unavailable — reconnect to the daemon, then Retry".to_string(),
            );
            return;
        };
        let mut parts = args.split_whitespace();
        let action = match parts.next().unwrap_or("status") {
            "status" => cockpit_proto::CuratorAction::Status,
            "run" => {
                let mut dry_run = false;
                let mut consolidate = false;
                for part in parts {
                    match part {
                        "--dry-run" => dry_run = true,
                        "--consolidate" => consolidate = true,
                        other => {
                            self.push_plain(format!("/curator: unknown run option `{other}`"));
                            return;
                        }
                    }
                }
                cockpit_proto::CuratorAction::Run {
                    dry_run,
                    consolidate,
                }
            }
            "pin" | "unpin" | "restore" => {
                let command = args.split_whitespace().next().unwrap();
                let Some(name) = parts.next() else {
                    self.push_plain(format!("/curator: usage {command} <name>"));
                    return;
                };
                match command {
                    "pin" => cockpit_proto::CuratorAction::Pin { name: name.into() },
                    "unpin" => cockpit_proto::CuratorAction::Unpin { name: name.into() },
                    _ => cockpit_proto::CuratorAction::Restore { name: name.into() },
                }
            }
            other => {
                self.push_plain(format!("/curator: unsupported action `{other}`"));
                return;
            }
        };
        let request = cockpit_proto::Request::Curator {
            project_root: self.launch.cwd.to_string_lossy().into_owned(),
            action,
        };
        let curator_key = AsyncActionKey::new("curator.command");
        if self.async_actions.has_pending_key(&curator_key) {
            return;
        }
        self.push_plain("/curator: pending".to_string());
        let operation = self.curator_blocking_operation();
        self.start_owned_blocking_action(
            operation,
            AsyncActionPolicy::Dedupe(curator_key),
            move || {
                let response = agent_runner::daemon_request_at_blocking(&endpoint, request)?;
                Ok(AsyncActionPayload::Text(format!("/curator: {response:?}")))
            },
        );
    }

    fn handle_goal_command(&mut self, args: &str) {
        let trimmed = args.trim();
        if trimmed.is_empty() || trimmed == "status" {
            self.show_goal_status();
            return;
        }
        match trimmed {
            "pause" => {
                self.set_goal_status(cockpit_proto::GoalDisposition::UserPaused, "/goal pause");
            }
            "resume" => {
                self.set_goal_status(cockpit_proto::GoalDisposition::Running, "/goal resume");
            }
            "clear" => self.clear_goal(),
            "edit" => {
                self.replace_composer_buffer("/goal ".to_string());
                self.push_plain(
                    "/goal edit: update the objective in the composer and submit.".to_string(),
                );
            }
            _ => {
                self.swap_primary_agent("Build");
                let (token_budget, objective) = match Self::parse_goal_create_args(trimmed) {
                    Ok(parsed) => parsed,
                    Err(message) => {
                        self.push_plain(format!("/goal: {message}"));
                        return;
                    }
                };
                if objective.is_empty() {
                    self.push_plain("/goal: objective must not be empty".to_string());
                    return;
                }
                self.create_goal(objective, token_budget);
            }
        }
    }

    fn parse_goal_create_args(input: &str) -> Result<(Option<i64>, String), String> {
        let mut words = input.split_whitespace();
        let mut budget = None;
        let mut objective = Vec::new();
        while let Some(word) = words.next() {
            if word == "--budget" {
                if budget.is_some() {
                    return Err("--budget may be specified only once".to_string());
                }
                let value = words
                    .next()
                    .ok_or_else(|| "--budget requires a positive integer".to_string())?;
                if value.starts_with("--") {
                    return Err("--budget requires a positive integer".to_string());
                }
                let parsed = value
                    .parse::<i64>()
                    .map_err(|_| "--budget requires a positive integer".to_string())?;
                if parsed <= 0 {
                    return Err("--budget requires a positive integer".to_string());
                }
                budget = Some(parsed);
            } else {
                objective.push(word);
            }
        }
        Ok((budget, objective.join(" ")))
    }

    /// `/skill <skill-name> [task]` — the universal dispatcher
    /// (implementation note). Invokes ANY discovered skill
    /// by name, including ones shadowed from the bare-`/<name>` sugar by a
    /// builtin collision. Bare `/skill` (no name) or an unknown name lists the
    /// available skills as a clear error — never a silent no-op. Trailing text
    /// after the name is forwarded as the accompanying task input.
    pub(super) fn handle_skill_command(&mut self, args: &str) {
        // Use the last complete daemon inventory snapshot (authorized for the
        // selected agent). No local filesystem discovery.
        let skills = self.visible_skill_summaries();
        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        match resolve_skill_dispatch(args, &names) {
            SkillDispatch::Invoke { name, task } => {
                let display = if task.is_empty() {
                    format!("/skill {name}")
                } else {
                    format!("/skill {name} {task}")
                };
                self.dispatch_skill_invocation(display, &name, &task);
            }
            SkillDispatch::Error(line) => {
                self.push_plain(line);
            }
        }
    }

    /// `/schedule` (GOALS §22): list active scheduled tasks, or `/schedule
    /// cancel <id>` to cancel one (the human-side cancel affordance — these
    /// run on the user's dime). Cancellation uses the response-bearing control
    /// channel so delivery and daemon rejection are visible.
    pub(super) fn handle_schedule_command(&mut self, args: &str) {
        let args = args.trim();
        if let Some(rest) = args.strip_prefix("cancel") {
            let job_id = rest.trim();
            if job_id.is_empty() {
                self.push_plain("/schedule: usage `/schedule cancel <id>`".to_string());
                return;
            }
            self.send_daemon_request(
                "/schedule",
                cockpit_proto::Request::CancelSchedule {
                    job_id: job_id.to_string(),
                },
                ControlApplied::ScheduleCancel {
                    command: "/schedule".to_string(),
                    job_id: job_id.to_string(),
                },
            );
            return;
        }
        // Bare `/schedule`: list.
        if self.active_schedules.is_empty() {
            self.push_plain("/schedule: no active scheduled tasks".to_string());
            return;
        }
        self.push_plain("/schedule: active —".to_string());
        let lines: Vec<String> = self
            .active_schedules
            .iter()
            .map(|(job_id, j)| {
                format!(
                    "  {}  (cancel: /schedule cancel {job_id})",
                    format_schedule_line(job_id, j)
                )
            })
            .collect();
        for line in lines {
            self.push_plain(line);
        }
    }

    /// `/ps` — list only the current session's running scheduled tasks, using
    /// the same per-task formatting `/schedule` shows. Empty state matches the
    /// spec. Current-session-scoped; never reaches other sessions (that's
    /// `/schedule`).
    pub(super) fn handle_ps_command(&mut self) {
        let ids = self.current_session_job_ids();
        if ids.is_empty() {
            self.push_plain("No background jobs in this session.".to_string());
            return;
        }
        self.push_plain("/ps: active in this session —".to_string());
        let lines: Vec<String> = ids
            .into_iter()
            .filter_map(|job_id| {
                self.active_schedules.get(&job_id).map(|j| {
                    format!(
                        "  {}  (stop: /stop {job_id})",
                        format_schedule_line(&job_id, j)
                    )
                })
            })
            .collect();
        for line in lines {
            self.push_plain(line);
        }
    }

    /// `/stop` — stop current-session scheduled tasks. `/stop <id>` cancels
    /// that one immediately (reusing the `/schedule cancel` `CancelSchedule` path);
    /// refuses an id outside the current session rather than reaching
    /// across. Bare `/stop` arms a `[y/N]` confirm to cancel them all.
    pub(super) fn handle_stop_command(&mut self, args: &str) {
        let job_id = args.trim();
        if job_id.is_empty() {
            self.arm_stop_confirm();
            return;
        }
        let in_session = self.current_session_job_ids().iter().any(|id| id == job_id);
        if !in_session {
            self.push_plain(format!(
                    "/stop: no scheduled task `{job_id}` in this session (use /schedule for other sessions)"
                ));
            return;
        }
        self.cancel_schedule(job_id, "/stop");
    }

    /// Handle `/mcp …` (GOALS §18a). Reads and mutations are queued as
    /// daemon-owned effects; completion lines arrive later through the
    /// correlated async-action drain.
    pub(super) fn handle_mcp_command(&mut self, arg: &str) {
        match parse_mcp_action(arg) {
            McpAction::List => self.mcp_list(),
            McpAction::Settings => {
                self.dialog = crate::tui::settings::Dialog::open_mcp(&self.launch.cwd);
            }
            McpAction::SetEnabled { id, enable } => self.mcp_set_enabled(id.as_deref(), enable),
            McpAction::Usage => {
                self.push_plain("Usage: /mcp [settings | list | on|off|toggle [id]]".to_string())
            }
        }
    }

    /// `/agent [name]` — switch the active primary (chat-owning) agent, or
    /// list the available primaries (`agent-switch-command-and-
    /// cycle.md`). With a `name`, validate it against the chat-ownable set
    /// (builtins `Plan`/`Build` + user-defined `primary`/`all`) and
    /// route a valid one through [`Self::swap_primary_agent`] (same
    /// confirmation line + start-a-session-first guard `/plan`/`/build`
    /// have); an unknown or subagent-only name prints an error naming the
    /// bad value in backticks plus the valid choices and does **not** switch.
    /// Bare `/agent` lists the primaries, marking the active one — it does
    /// not switch and does not open a picker.
    pub(super) fn handle_agent_command(&mut self, arg: &str) {
        let order = self.inventory_agent_names();
        match agent_command_outcome(arg, &self.launch.agent_name, &order) {
            // A valid named target: route through the shared swap entry point
            // (its confirmation line + start-a-session-first guard apply).
            AgentCommandOutcome::Switch(name) => self.swap_primary_agent(&name),
            // Bare `/agent` list, or an error naming the bad value — both are
            // plain history lines; neither switches.
            AgentCommandOutcome::Message(line) => {
                self.push_plain(line);
            }
        }
    }

    /// `/assistant <name>` — open the persistent assistant's latest session,
    /// creating one when none exists. Uses the same resume path as the
    /// sessions browser so daemon attach, transcript rebuild, and workspace
    /// trust behavior stay centralized.
    pub(super) fn handle_assistant_command(&mut self, arg: &str) {
        let name = arg.trim();
        if name.is_empty() {
            self.push_plain("Usage: /assistant <name>".to_string());
            return;
        }
        if let Err(error) = cockpit_core::assistants::validate_assistant_name(name) {
            self.push_plain(format!("/assistant: {error}"));
            return;
        }
        let request = cockpit_proto::Request::ResolveAssistantSession {
            assistant_id: name.to_string(),
            project_root: self.launch.cwd.to_string_lossy().into_owned(),
            mode: cockpit_proto::AssistantSessionResolutionMode::MostRecentOrCreate,
        };
        let source_session_id = self.launch.session_id;
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("assistant.resolve"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                let resolution =
                    agent_runner::resolve_assistant_session_blocking(lifecycle, request)?;
                match resolution.response {
                    cockpit_proto::Response::AssistantSessionResolved { session, .. } => {
                        Ok(AsyncActionPayload::AssistantSessionResolved {
                            session_id: session.session_id,
                            source_session_id,
                            startup_notice: resolution.startup_notice,
                            promoted_from_ephemeral: resolution.promoted_from_ephemeral,
                        })
                    }
                    other => Err(format!("unexpected assistant response: {other:?}")),
                }
            },
        );
    }

    /// `/side [end]`: throwaway side conversation forked from here.
    ///
    /// - bare `/side` forks the current session into an **ephemeral** fork
    ///   and switches the TUI onto it (full prior history stays visible).
    /// - `/side end` returns to the unchanged main session and discards the
    ///   ephemeral fork.
    ///
    /// `/side` while already in a side conversation is a flat, deterministic
    /// no-op (a persisted branch is `/fork`, not nested `/side`).
    pub(super) fn handle_side_command(&mut self, args: &str) {
        let arg = args.trim();
        if arg.eq_ignore_ascii_case("end") {
            if self.side_conversation.is_some() {
                self.end_side_conversation(true);
            } else {
                self.push_plain("/side: not in a side conversation".to_string());
            }
            return;
        }
        if !arg.is_empty() {
            self.push_plain("Usage: `/side` to start, `/side end` to discard".to_string());
            return;
        }
        if self.side_conversation.is_some() {
            // Deterministic no-op: already in a side conversation, don't nest.
            self.push_plain(
                "/side: already in a side conversation (`/side end` to discard)".to_string(),
            );
            return;
        }
        self.enter_side_conversation();
    }

    pub(super) fn handle_fork_command(&mut self, args: &str) {
        if !args.trim().is_empty() {
            self.push_plain("Usage: `/fork`".to_string());
            return;
        }
        if self.fork_preconditions_ok() {
            self.enter_fork_pick_mode();
        }
    }

    /// `/sandbox` (sandboxing part 2): no arg toggles, `on`/`off` set
    /// explicitly. Sends `SetSandbox` to the daemon for the attached
    /// session; the resulting state is surfaced via the `SandboxState`
    /// event → toast. Effective immediately for subsequent tool calls.
    pub(super) fn handle_sandbox_command(&mut self, args: &str) {
        let command = match parse_sandbox_arg(args) {
            Ok(command) => command,
            Err(other) => {
                self.push_plain(format!(
                        "/sandbox: unknown arg `{other}` - use off, on, container, container-readonly, or network on/off"
                    ));
                return;
            }
        };
        let (mode, network) = match command {
            SandboxCommand::Cycle => (
                Some(next_sandbox_mode(
                    self.sandbox_mode,
                    &self.host_capabilities,
                )),
                None,
            ),
            SandboxCommand::Set(mode) => {
                let snapshot = self.host_capabilities.clone();
                match decide_sandbox_set(mode, &snapshot, || self.refresh_host_capabilities()) {
                    Ok(mode) => (Some(mode), None),
                    Err(instruct) => {
                        self.push_plain(format!("/sandbox: {}", instruct.display()));
                        return;
                    }
                }
            }
            SandboxCommand::Network(enabled) => {
                if !self.sandbox_mode.is_container() {
                    self.push_plain(
                        "/sandbox: network only applies to container sandboxes".to_string(),
                    );
                    return;
                }
                (None, Some(enabled))
            }
        };
        self.send_daemon_request(
            "/sandbox",
            cockpit_proto::Request::SetSandbox {
                mode,
                container_network_enabled: network,
            },
            ControlApplied::None,
        );
    }

    /// `/sandbox-escalate [allow|disallow]`: session-only switch for whether
    /// an explicit unsandboxed retry path may be offered after sandboxed
    /// command failures. Approval mode still gates any allowed escalation.
    pub(super) fn handle_sandbox_escalate_command(&mut self, args: &str) {
        match parse_sandbox_escalation_arg(args) {
            Ok(SandboxEscalationCommand::Status) => {
                self.push_plain(format!(
                    "/sandbox-escalate: {}",
                    if self.sandbox_escalation_enabled {
                        "allowed"
                    } else {
                        "disallowed"
                    }
                ));
            }
            Ok(SandboxEscalationCommand::Set(enabled)) => {
                self.send_daemon_request(
                    "/sandbox-escalate",
                    cockpit_proto::Request::SetSandboxEscalation { enabled },
                    ControlApplied::None,
                );
            }
            Err(other) => {
                self.push_plain(format!(
                    "/sandbox-escalate: unknown arg `{other}` - use allow, disallow, or no arg for status"
                ));
            }
        }
    }

    pub(super) fn handle_doctor_command(&mut self) {
        let input = self.doctor_snapshot_input();
        let clipboard_recovery = self.clipboard_recovery;
        self.push_plain("/doctor: collecting diagnostics…".to_string());
        let operation = self.doctor_blocking_operation();
        self.start_owned_blocking_action(
            operation,
            AsyncActionPolicy::Replace(AsyncActionKey::new("doctor.snapshot")),
            move || {
                let snapshot = cockpit_core::diagnostics::tui_snapshot(input)
                    .map_err(|error| format!("/doctor: {error}"))?;
                let mut rendered = cockpit_core::diagnostics::render(&snapshot);
                if let Ok(dir) = crate::clipboard::recovery::recovery_dir_path() {
                    let (lines, _) =
                        crate::clipboard::recovery::doctor_lines(clipboard_recovery, &dir);
                    rendered.push('\n');
                    rendered.push_str(&lines.join("\n"));
                }
                Ok(AsyncActionPayload::DoctorSnapshot(rendered))
            },
        );
    }

    pub(super) fn doctor_snapshot_input(&self) -> cockpit_core::diagnostics::DiagnosticsInput {
        cockpit_core::diagnostics::DiagnosticsInput {
            cwd: self.launch.cwd.clone(),
            session_id: self.launch.session_id,
            session_short_id: self.launch.session_short_id.clone(),
            active_agent: self.launch.agent_name.clone(),
            active_model: self.launch.active_model.clone(),
            pending_model_selection: self.pending_model_selection.as_ref().map(|pending| {
                format!(
                    "pending {}: {}/{}",
                    pending.selection_id, pending.requested.provider, pending.requested.model
                )
            }),
            sandbox_enabled: Some(!self.no_sandbox),
            // The TUI is an authority-free daemon client. It must not infer a
            // live accepted-turn media capability from the session id.
            media_authority_usable: false,
        }
    }

    /// `/preflight [on|off]`: flip request preflight for the running session
    /// (implementation note). `on`/`off` set it explicitly; a bare
    /// invocation toggles the current effective state. **Session-only /
    /// in-memory** — the driver holds the override (precedence over config) and
    /// never writes config; reverts on restart. The resulting state arrives
    /// back via the `PreflightState` broadcast → mirror + toast.
    pub(super) fn handle_preflight_command(&mut self, args: &str) {
        let enabled = match args.trim().to_ascii_lowercase().as_str() {
            "" => None, // bare → toggle the current effective state
            "on" | "enable" | "enabled" => Some(true),
            "off" | "disable" | "disabled" => Some(false),
            other => {
                self.push_plain(format!(
                    "/preflight: unknown arg `{other}` — use `on`, `off`, or no arg to toggle"
                ));
                return;
            }
        };
        self.send_daemon_request(
            "/preflight",
            cockpit_proto::Request::SetPreflight { enabled },
            ControlApplied::None,
        );
    }

    /// `/tool-calls [hide|show]` filters model tool-call rows from the main
    /// assistant transcript. This is an in-memory, per-view presentation
    /// setting: it never changes model context, daemon history, or storage.
    pub(super) fn handle_tool_calls_command(&mut self, args: &str) {
        if !matches!(self.transcript_view, TranscriptViewMeta::Main) {
            self.show_toast(
                "/tool-calls is available in the main assistant view",
                ToastKind::Info,
            );
            return;
        }
        let hide = match args.trim().to_ascii_lowercase().as_str() {
            "" | "toggle" => !self.hide_tool_calls,
            "hide" | "on" => true,
            "show" | "off" => false,
            other => {
                self.show_toast(
                    format!("/tool-calls: unknown arg `{other}` — use `hide`, `show`, or no arg to toggle"),
                    ToastKind::Info,
                );
                return;
            }
        };
        if self.hide_tool_calls == hide {
            return;
        }
        self.hide_tool_calls = hide;
        self.history_render_cache_clear();
        self.mark_chat_geometry_dirty_from(0);
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
        self.show_toast(
            if hide {
                "Tool-call rows hidden in this view"
            } else {
                "Tool-call rows shown in this view"
            },
            ToastKind::Info,
        );
    }

    pub(super) fn handle_longcache_command(&mut self, args: &str) {
        let enabled = match args.trim().to_ascii_lowercase().as_str() {
            "" => None,
            "on" | "enable" | "enabled" => Some(true),
            "off" | "disable" | "disabled" => Some(false),
            other => {
                self.push_plain(format!(
                    "/longcache: unknown arg `{other}` — use `on`, `off`, or no arg to toggle"
                ));
                return;
            }
        };
        self.send_daemon_request(
            "/longcache",
            cockpit_proto::Request::SetLongcache { enabled },
            ControlApplied::None,
        );
    }

    /// `/toggle-redaction [env|file|ssh]` (alias `/toggle-redact`): flip a
    /// redaction source for the running session. `env` flips environment-
    /// variable redaction, `file` flips environment-file redaction, and `ssh`
    /// flips private SSH-key redaction; a bare invocation opens a multiselect
    /// pre-checked to the current state. All effects are **session-only /
    /// in-memory** — the daemon rebuilds the effective redaction table for
    /// subsequent outbound prompts and never writes config. `scrub()` stays
    /// non-bypassable.
    pub(super) fn handle_toggle_redaction_command(&mut self, args: &str) {
        match args.trim().to_ascii_lowercase().as_str() {
            "" => self.open_redaction_toggle_dialog(),
            "env" | "environment" => {
                self.send_redaction_toggle(Some(!self.redact_scan_environment), None, None);
            }
            "file" | "files" => {
                self.send_redaction_toggle(None, Some(!self.redact_scan_dotenv), None);
            }
            "ssh" | "ssh-keys" | "keys" => {
                self.send_redaction_toggle(None, None, Some(!self.redact_scan_ssh_keys));
            }
            other => {
                self.push_plain(format!(
                        "/toggle-redaction: unknown arg `{other}` — use `env`, `file`, `ssh`, or no arg for the picker"
                    ));
            }
        }
    }

    /// `/caffeinate [toggle|on|off|until-idle]`: suppress system sleep +
    /// lid-close so agents survive a closed lid. Daemon-owned state — this
    /// just sends the request; the daemon acquires/releases the OS
    /// assertion and broadcasts a `CaffeinateState` event back (→ toast +
    /// ☕ glyph). Bare command toggles.
    pub(super) fn handle_caffeinate_command(&mut self, args: &str) {
        let mode = match cockpit_proto::CaffeinateMode::parse(args) {
            Ok(m) => m,
            Err(other) => {
                self.push_plain(format!(
                        "/caffeinate: unknown arg `{other}` — use `on`, `off`, `until-idle`, or no arg to toggle"
                    ));
                return;
            }
        };
        self.send_daemon_request(
            "/caffeinate",
            cockpit_proto::Request::SetCaffeinate { mode },
            ControlApplied::None,
        );
    }

    pub(super) fn handle_pin_context_command(&mut self, args: &str) {
        let text = args.trim();
        if text.is_empty() {
            self.push_plain(
                "/pin-context: usage `/pin-context <text>` — pins text verbatim for /compact"
                    .to_string(),
            );
            return;
        }
        self.send_daemon_request(
            "/pin-context",
            cockpit_proto::Request::Pin {
                text: text.to_string(),
            },
            ControlApplied::PinContext {
                text: text.to_string(),
            },
        );
    }

    /// `/copy [N] [markdown|plain|rich] [file <path>]` — copy an earlier
    /// assistant response to the system clipboard, or (with the `file`
    /// form) write it to a user path with an atomic no-clobber guarantee.
    /// `N` selects newest-first among nonempty assistant messages (`1` is
    /// the last response, the bare-`/copy` default). Default format is
    /// `markdown` (the raw response verbatim); `plain` strips the
    /// markdown; `rich` copies HTML to the clipboard or writes the HTML
    /// rendering to a file. Clipboard forms mirror the context-menu copy
    /// path (`execute_context_menu_action`) and reuse the clipboard
    /// module; the file form runs off the event loop (GOALS: input stays
    /// responsive) via [`Self::start_copy_to_file_action`]. Surfaces
    /// feedback via a toast.
    pub(super) fn handle_copy_command(&mut self, arg: &str) {
        if arg.trim().eq_ignore_ascii_case("pick") {
            self.enter_copy_pick_mode();
            return;
        }
        let command = match parse_copy_command(arg) {
            Ok(c) => c,
            Err(e) => {
                self.show_toast(
                    format!("{e}. Usage: `/copy [N] [markdown|plain|rich] [file <path>]`"),
                    ToastKind::Info,
                );
                return;
            }
        };
        let Some(text) = select_agent_text(&self.history, command.n) else {
            self.show_toast(
                match command.n {
                    Some(n) => format!("/copy: no assistant response at position {n}."),
                    None => "No response to copy yet.".to_string(),
                },
                ToastKind::Info,
            );
            return;
        };

        if let Some(path) = command.file {
            self.start_copy_to_file_action(path, command.format, text);
            return;
        }

        let (msg, kind) = match command.format {
            CopyFormat::Markdown => {
                match crate::clipboard::copy_plain(&text, self.clipboard_recovery) {
                    Ok(result) => super::copy_actions::describe_delivered(
                        &result,
                        "Copied last response (markdown).".to_string(),
                    ),
                    Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
            CopyFormat::Plain => {
                let plain = crate::clipboard::markdown_to_plain(&text);
                match crate::clipboard::copy_plain(&plain, self.clipboard_recovery) {
                    Ok(result) => super::copy_actions::describe_delivered(
                        &result,
                        "Copied last response (plain).".to_string(),
                    ),
                    Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
            CopyFormat::Rich => {
                let html = crate::clipboard::markdown_to_html(&text);
                match crate::clipboard::copy_rich(&text, &html, self.clipboard_recovery) {
                    Ok(result) if crate::clipboard::feedback::classify(&result).downgraded => {
                        super::copy_actions::describe_delivered(
                            &result,
                            "Copied last response as plain text                          (rich copy unavailable on this route)."
                                .to_string(),
                        )
                    }
                    Ok(result) => super::copy_actions::describe_delivered(
                        &result,
                        "Copied last response (rich).".to_string(),
                    ),
                    Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
        };
        self.show_toast(msg, kind);
    }

    /// The exact bytes `/copy … file` would publish for `text` rendered in
    /// `format`. Pure so the parser/selection/render pipeline is testable
    /// without touching the filesystem.
    pub(super) fn render_copy_file_payload(format: CopyFormat, text: &str) -> Vec<u8> {
        match format {
            CopyFormat::Markdown => text.as_bytes().to_vec(),
            CopyFormat::Plain => crate::clipboard::markdown_to_plain(text).into_bytes(),
            CopyFormat::Rich => crate::clipboard::markdown_to_html(text).into_bytes(),
        }
    }

    /// Dispatch `/copy … file <path>` off the event loop. A second
    /// `/copy … file` request before this one finishes replaces it
    /// ([`crate::tui::async_action::AsyncActionPolicy::Replace`]): the
    /// first request's disk write may still complete, but its result is
    /// discarded by the runner (never applied to a since-changed view) —
    /// see `crate::tui::app::async_actions::apply_async_action_result`.
    pub(super) fn start_copy_to_file_action(
        &mut self,
        path: String,
        format: CopyFormat,
        text: String,
    ) {
        let target = std::path::PathBuf::from(&path);
        let payload = Self::render_copy_file_payload(format, &text);
        if payload.len() > crate::clipboard::file_publish::MAX_PAYLOAD_BYTES {
            self.show_toast(
                format!(
                    "/copy file: selection too large ({} bytes, max {}).",
                    payload.len(),
                    crate::clipboard::file_publish::MAX_PAYLOAD_BYTES
                ),
                ToastKind::Error,
            );
            return;
        }
        self.show_toast(format!("/copy file {path}: writing…"), ToastKind::Info);

        // M7: signal cancellation to whatever `/copy … file` publish is
        // still in flight (if any) before superseding it — otherwise the
        // superseded publish always runs to completion unnoticed even
        // though `AsyncActionPolicy::Replace` (below) means its result
        // will never reach a toast. Real cancellation, not merely
        // discarding the eventual result: at its one checkpoint (temp file
        // durable, before the atomic rename) it can still abandon before
        // ever touching the target name.
        if let Some(previous) = self.copy_file_cancel.take() {
            previous.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.copy_file_cancel = Some(std::sync::Arc::clone(&cancel));

        self.async_actions.start_blocking(
            AsyncActionKind::Blocking("copy.file"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("copy.file")),
            move || {
                crate::clipboard::file_publish::publish_no_clobber(&target, &payload, &move || {
                    cancel.load(std::sync::atomic::Ordering::Relaxed)
                })
                .map(|published| AsyncActionPayload::CopyToFile {
                    path: published.path,
                    bytes_written: published.bytes_written,
                    durability_confirmed: published.durability_confirmed,
                })
                .map_err(|error| error.to_string())
            },
        );
    }

    /// `/rename <title>` manually renames the current session. `/rename`
    /// without a title asks the utility model to generate a fresh auto title
    /// from the durable user-authored transcript.
    pub(super) fn handle_rename_command(&mut self, arg: &str) {
        let title = arg.trim();
        // Authoritative current session: the live runner if attached,
        // else the last-attached id tracked on launch info.
        let session_id = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => Some(runner.session_id()),
            _ => self.launch.session_id,
        };
        let Some(session_id) = session_id else {
            self.push_plain("/rename: no active session yet — send a message first".to_string());
            return;
        };
        if title.is_empty() {
            let Some(endpoint) = self.attached_daemon_endpoint() else {
                self.push_plain("/rename: daemon is not attached".to_string());
                return;
            };
            self.push_plain("/rename: generating".to_string());
            let request = cockpit_proto::Request::AutoTitle { session_id };
            self.async_actions.start_blocking(
                AsyncActionKind::Internal("rename.auto"),
                AsyncActionPolicy::AllowConcurrent,
                move || match agent_runner::daemon_request_at_blocking(&endpoint, request)? {
                    cockpit_proto::Response::AutoTitle { title, .. } => {
                        Ok(AsyncActionPayload::Text(title))
                    }
                    other => Err(format!("unexpected auto-title response: {other:?}")),
                },
            );
            return;
        }
        let req = cockpit_proto::Request::RenameSession {
            session_id,
            title: title.to_string(),
        };
        let title = title.to_string();
        let Some(endpoint) = self.attached_daemon_endpoint() else {
            self.push_plain("/rename: daemon is not attached".to_string());
            return;
        };
        self.push_plain("/rename: pending".to_string());
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("rename"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                agent_runner::daemon_request_at_blocking(&endpoint, req)
                    .map(|_| AsyncActionPayload::Text(title))
            },
        );
    }

    /// `/export [debug]` — export the current session into
    /// `{cwd}/.cockpit/exports/`. Default exports the live transcript as
    /// `<short_id>.json` (user-facing form, GOALS §14); `debug` exports
    /// the full CLI bundle `.zip`. Both overwrite their own prior file
    /// and surface success/failure as a chat line, never a panic.
    pub(super) fn handle_export_command(&mut self, arg: &str) {
        // Authoritative current session: the live runner if attached,
        // else the last-attached ids tracked on launch info.
        let (session_id, short_id) = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => (Some(runner.session_id()), Some(runner.short_id.clone())),
            _ => (self.launch.session_id, self.launch.session_short_id.clone()),
        };
        let Some(session_id) = session_id else {
            self.push_plain("/export: no active session yet — send a message first".to_string());
            return;
        };
        // `<short_id>`, falling back to the full UUID (matching the CLI's
        // `default_output_path`).
        let file_stem = short_id
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| session_id.to_string());
        let exports_dir = self.launch.cwd.join(".cockpit").join("exports");

        if arg.trim() == "debug" {
            self.export_debug_bundle(session_id, &file_stem, &exports_dir);
        } else {
            self.export_transcript_json(&file_stem, &exports_dir);
        }
    }

    /// `/version` — render a transcript message with the running cockpit
    /// version (Cargo package version) and the OS/platform string cockpit
    /// already gathers for the cached system block
    /// ([`cockpit_host::sysinfo::os_string`]); no build metadata. One `Plain` line
    /// per field, matching how other informational commands list output.
    pub(super) fn handle_version_command(&mut self) {
        self.push_plain(format!("cockpit {}", env!("CARGO_PKG_VERSION")));
        self.push_plain(format!("OS: {}", cockpit_host::sysinfo::os_string()));
    }

    /// `/note <text>` — append a session-history note to self. The note is a
    /// durable `user_note` session event (rendered as a distinct transcript
    /// row, included in exports) that is **never** sent to the model and never
    /// triggers an inference call (rehydration skips `user_note` events). Bare
    /// `/note` (empty / whitespace-only text) shows usage only; running it
    /// before a session exists shows the same "send a message first" error as
    /// `/rename`/`/export` and creates no phantom session.
    pub(super) fn handle_note_command(&mut self, arg: &str) {
        let text = arg.trim();
        if text.is_empty() {
            self.push_plain("Usage: `/note <text>`".to_string());
            return;
        }
        // Authoritative current session: the live runner if attached, else the
        // last-attached id tracked on launch info (same resolution as
        // `/rename`/`/export`).
        let session_id = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => Some(runner.session_id()),
            _ => self.launch.session_id,
        };
        let Some(session_id) = session_id else {
            self.push_plain("/note: no active session yet — send a message first".to_string());
            return;
        };
        let req = cockpit_proto::Request::RecordSessionNote {
            session_id,
            text: text.to_string(),
        };
        let text = text.to_string();
        let Some(endpoint) = self.attached_daemon_endpoint() else {
            self.push_plain("/note: daemon is not attached".to_string());
            return;
        };
        self.push_plain("/note: pending".to_string());
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("note"),
            AsyncActionPolicy::AllowConcurrent,
            move || match agent_runner::daemon_request_at_blocking(&endpoint, req) {
                Ok(cockpit_proto::Response::NoteRecorded { .. }) => {
                    Ok(AsyncActionPayload::NoteRecorded { text })
                }
                Ok(_) => Err("unexpected daemon response".to_string()),
                Err(e) => Err(e),
            },
        );
    }

    /// Handle the `/leaks` command. Bare `/leaks` and `/leaks list` open the
    /// interactive [`LeaksPane`] (metadata list + authenticated reveal);
    /// `/leaks rotate|delete <id>` remain metadata-only textual passthrough.
    pub(super) fn handle_leaks_command(&mut self, args: &str) {
        let trimmed = args.trim();
        if trimmed.is_empty() || trimmed == "list" {
            self.open_leaks_pane();
            return;
        }
        let Some(request) = leaks_request(args) else {
            self.push_plain(
                "/leaks: usage `/leaks`, `/leaks list`, `/leaks rotate <id> <accept|dismiss|rotated>`, `/leaks delete <id>`"
                    .to_string(),
            );
            return;
        };
        let label = match &request {
            cockpit_proto::Request::ListLeakReports { .. } => "leaks-list",
            cockpit_proto::Request::MarkLeakRotated { .. } => "leaks-rotate",
            cockpit_proto::Request::DeleteLeakReport { .. } => "leaks-delete",
            _ => "leaks",
        };
        let Some(endpoint) = self.attached_daemon_endpoint() else {
            self.push_plain("/leaks: daemon is not attached".to_string());
            return;
        };
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc(label),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                let text = leak_response_text(agent_runner::daemon_request_at_blocking(
                    &endpoint, request,
                ));
                Ok(AsyncActionPayload::Text(text))
            },
        );
    }

    /// `/sealed` — the owner-remoted frontend over `parse_sealed_command`. Parses
    /// locally, NEVER opens the vault, and routes only sealed-owner RPCs:
    /// metadata commands render safe text; create/rotate/replace open a no-echo
    /// overlay; recover reveals into an ephemeral overlay; delete has no owner RPC.
    pub(super) fn handle_sealed_command(&mut self, args: &str) {
        use crate::tui::sealed_overlay::{SealedDispatch, SealedScopeContext, plan_dispatch};
        let tokens: Vec<&str> = args.split_whitespace().collect();
        // Route through the redacting funnel: a parse failure surfaces ONLY a
        // fixed, content-free message, so a mistyped secret on the command line
        // never reaches the transcript, history, or exit tail.
        let cmd = match crate::tui::sealed_overlay::parse_sealed_tokens(&tokens) {
            Ok(cmd) => cmd,
            Err(message) => {
                self.push_plain(message.to_string());
                return;
            }
        };
        // Every sealed-owner operation rides the attached session's persistent
        // daemon connection (one stable `client_instance_id`), so begin/apply/
        // cancel share the minting connection the capability is bound to.
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            self.push_plain("/sealed: attach a session first".to_string());
            return;
        };
        let ctx = SealedScopeContext {
            session_id: runner.session_id().to_string(),
            // The attached runner's project id is the daemon-established
            // canonical project identity for this exact session. Reusing it
            // avoids a second, fallible filesystem canonicalization here and
            // keeps a project-scoped sealed operation bound to its session.
            project_key: runner.project_id.clone(),
        };
        match plan_dispatch(&cmd, &ctx) {
            SealedDispatch::Metadata(request) => self.dispatch_sealed_metadata(request),
            SealedDispatch::Write(plan) => self.begin_sealed_write(plan),
            SealedDispatch::Recover { record_id } => self.recover_sealed_into_overlay(record_id),
            SealedDispatch::Unsupported(message) => self.push_plain(message),
        }
    }

    /// The attached session's persistent request binding, or `None` when no
    /// session is attached.
    fn attached_sealed_binding(&self) -> Option<agent_runner::AttachedRequestBinding> {
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => Some(runner.attached_request_binding()),
            _ => None,
        }
    }

    fn start_sealed_effect(
        &mut self,
        binding: agent_runner::AttachedRequestBinding,
        pending: PendingSealedOperation,
        future: impl std::future::Future<Output = Result<cockpit_proto::Response, String>>
        + Send
        + 'static,
    ) {
        let operation_id = pending.operation_id();
        let session_id = binding.session_id();
        let attachment_epoch = binding.attachment_epoch();
        self.pending_sealed_operations.insert(operation_id, pending);
        self.async_actions.start(
            AsyncActionKind::DaemonRpc("sealed.effect"),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let response = future.await;
                Ok(AsyncActionPayload::Sealed(SealedCompletion {
                    operation_id,
                    session_id,
                    attachment_epoch,
                    response,
                }))
            },
        );
    }

    fn sealed_binding_is_current(&self, session_id: uuid::Uuid, attachment_epoch: u64) -> bool {
        self.attached_sealed_binding().is_some_and(|binding| {
            binding.session_id() == session_id && binding.attachment_epoch() == attachment_epoch
        })
    }

    /// Send a metadata-only sealed-owner RPC over the attached binding and render
    /// its safe response text. Never carries or renders a literal.
    fn dispatch_sealed_metadata(&mut self, request: cockpit_proto::Request) {
        let Some(binding) = self.attached_sealed_binding() else {
            self.push_plain("/sealed: attach a session first".to_string());
            return;
        };
        let operation_id = uuid::Uuid::new_v4();
        let request_binding = binding.clone();
        self.start_sealed_effect(
            binding.clone(),
            PendingSealedOperation::Metadata { operation_id },
            async move { request_binding.request(request).await },
        );
    }

    /// Begin a create/replace/rotate write: mint the single-use capability over
    /// the attached binding, then open the no-echo overlay bound to it. The
    /// literal is collected later, in the overlay, and never before.
    fn begin_sealed_write(&mut self, plan: crate::tui::sealed_overlay::SealedWritePlan) {
        let Some(binding) = self.attached_sealed_binding() else {
            self.push_plain("/sealed: attach a session first".to_string());
            return;
        };
        let operation_id = uuid::Uuid::new_v4();
        let request_binding = binding.clone();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let worker_active = std::sync::Arc::clone(&active);
        self.start_sealed_effect(
            binding.clone(),
            PendingSealedOperation::BeginWrite {
                operation_id,
                binding: binding.clone(),
                active,
                disposition: plan.disposition,
                label: plan.label,
            },
            async move {
                let response = request_binding.request(plan.begin).await?;
                if let cockpit_proto::Response::SealedOwnerOperationBegun { capability_id, .. } =
                    &response
                    && !worker_active.load(std::sync::atomic::Ordering::Acquire)
                {
                    let settlement = request_binding
                        .request(crate::tui::sealed_overlay::cancel_request(capability_id))
                        .await;
                    return match settlement {
                        Ok(cockpit_proto::Response::SealedOwnerOperationCancelled { .. }) => {
                            Err("sealed write cancelled by attachment transition".to_string())
                        }
                        _ => Err("sealed capability settlement failed".to_string()),
                    };
                }
                Ok(response)
            },
        );
    }

    /// Apply a create/replace/rotate write. The `literal` (a zeroizing
    /// `SensitiveWireLiteral`) is moved straight into the apply frame; it never
    /// enters completion state, the transcript, history, or a log. The request
    /// is moved directly into the async attached-binding effect.
    pub(super) fn apply_sealed_write(
        &mut self,
        capability_id: &str,
        literal: cockpit_proto::SensitiveWireLiteral,
        summary: Option<String>,
    ) {
        let Some(binding) = self.sealed_capability_bindings.remove(capability_id) else {
            // The exact originating binding was surrendered. Never redirect a
            // single-use capability to a replacement session/epoch.
            drop(literal);
            self.push_plain("/sealed: capability is no longer live".to_string());
            return;
        };
        let capability_id = capability_id.to_string();
        let request = crate::tui::sealed_overlay::apply_write_request(&capability_id, literal);
        let operation_id = uuid::Uuid::new_v4();
        let request_binding = binding.clone();
        self.start_sealed_effect(
            binding.clone(),
            PendingSealedOperation::ApplyWrite {
                operation_id,
                capability_id: capability_id.clone(),
                binding: binding.clone(),
                summary,
            },
            async move {
                match request_binding.request(request).await {
                    Ok(response @ cockpit_proto::Response::SealedOwnerOperationApplied { .. }) => {
                        Ok(response)
                    }
                    other => {
                        let settlement = request_binding
                            .request(crate::tui::sealed_overlay::cancel_request(&capability_id))
                            .await;
                        match settlement {
                            Ok(cockpit_proto::Response::SealedOwnerOperationCancelled {
                                spent: true,
                            }) => {}
                            // Apply may already have consumed the capability before
                            // returning an error; `spent: false` is the exact
                            // fail-closed receipt for that state.
                            Ok(cockpit_proto::Response::SealedOwnerOperationCancelled {
                                spent: false,
                            }) => {}
                            Ok(_) | Err(_) => {
                                return Err("sealed capability settlement failed".to_string());
                            }
                        }
                        other
                    }
                }
            },
        );
    }

    /// Cancel a minted capability (dismiss): spend its single-use compare-and-swap
    /// over the same binding without performing the operation.
    pub(super) fn cancel_sealed_capability(&mut self, capability_id: &str) {
        let Some(binding) = self.sealed_capability_bindings.remove(capability_id) else {
            return;
        };
        let operation_id = uuid::Uuid::new_v4();
        let capability_id = capability_id.to_string();
        let request_binding = binding.clone();
        self.start_sealed_effect(
            binding.clone(),
            PendingSealedOperation::Cancel {
                operation_id,
                capability_id: capability_id.clone(),
                binding: binding.clone(),
            },
            async move {
                request_binding
                    .request(crate::tui::sealed_overlay::cancel_request(&capability_id))
                    .await
            },
        );
    }

    /// Exit/interrupt teardown for an open `/sealed` overlay. If a WRITE is
    /// pending, zeroize its typed buffer and send a best-effort
    /// `CancelSealedOwnerOperation` over the still-live attached binding BEFORE
    /// the runner/daemon is torn down — otherwise a Ctrl-C×2 exit would leave the
    /// minted capability live until its server-side expiry. Fail-safe: with no
    /// session/binding it just drops (the buffer is already zeroized) and never
    /// blocks exit. A recover reveal needs no cancel; its plaintext lives only in
    /// the alt-screen buffer (never in history/exit-tail) and is scrubbed on drop.
    pub(super) fn teardown_sealed_overlay(&mut self) {
        let Overlay::Sealed(mut overlay) = std::mem::take(&mut self.overlay) else {
            return;
        };
        if let Some(capability_id) = overlay.take_pending_write_capability() {
            self.cancel_sealed_capability(&capability_id);
        }
        // `overlay` drops here, zeroizing any reveal/input buffer.
    }

    /// Exit settlement for every capability whose id is already known. Uses
    /// the minting session/epoch binding retained with the capability and
    /// awaits a typed spent/already-spent receipt before runner teardown.
    pub(super) async fn settle_known_sealed_capabilities_before_shutdown(&mut self) {
        for pending in self.pending_sealed_operations.values() {
            pending.invalidate();
        }
        let overlay_capability = match std::mem::take(&mut self.overlay) {
            Overlay::Sealed(mut overlay) => overlay.take_pending_write_capability(),
            other => {
                self.overlay = other;
                None
            }
        };
        let mut settlements = self.sealed_capability_bindings.drain().collect::<Vec<_>>();
        if let Some(capability_id) = overlay_capability
            && !settlements.iter().any(|(id, _)| id == &capability_id)
        {
            tracing::warn!(
                capability_id = %capability_id,
                "sealed overlay lost its originating settlement binding"
            );
        }
        for pending in self.pending_sealed_operations.values() {
            match pending {
                PendingSealedOperation::ApplyWrite {
                    capability_id,
                    binding,
                    ..
                }
                | PendingSealedOperation::Cancel {
                    capability_id,
                    binding,
                    ..
                } if !settlements.iter().any(|(id, _)| id == capability_id) => {
                    settlements.push((capability_id.clone(), binding.clone()));
                }
                _ => {}
            }
        }
        for (capability_id, binding) in settlements {
            let receipt = binding
                .request(crate::tui::sealed_overlay::cancel_request(&capability_id))
                .await;
            if !matches!(
                receipt,
                Ok(cockpit_proto::Response::SealedOwnerOperationCancelled {
                    spent: true | false
                })
            ) {
                tracing::warn!(
                    capability_id = %capability_id,
                    "sealed capability shutdown settlement was not confirmed"
                );
            }
        }
    }

    /// The pointer-dismiss entry: a left-click on an open `/sealed` overlay. Takes
    /// the overlay out, dismisses it (cancel a pending write / hide a reveal), and
    /// dispatches the resulting cancel exactly as a keyboard dismiss does.
    pub(super) fn dismiss_sealed_overlay_via_pointer(&mut self) {
        use crate::tui::sealed_overlay::SealedOverlayOutcome;
        let Overlay::Sealed(mut overlay) = std::mem::take(&mut self.overlay) else {
            return;
        };
        let outcome = overlay.pointer_dismiss();
        match outcome {
            SealedOverlayOutcome::Cancel { capability_id } => {
                self.cancel_sealed_capability(&capability_id);
            }
            SealedOverlayOutcome::Close => {
                self.leaks_reveal_clear_pending = true;
            }
            // A pointer dismiss never applies or stays.
            SealedOverlayOutcome::Apply { .. } | SealedOverlayOutcome::Stay => {}
        }
    }

    /// Recover: mint a recover capability and apply it over ONE connection, then
    /// install the revealed plaintext directly into the reveal overlay. The
    /// plaintext travels straight from the daemon response into the ephemeral
    /// zeroizing buffer. It crosses the async completion channel only inside
    /// `SensitiveWireLiteral`, whose debug/serialization surfaces are redacted,
    /// and never enters transcript, history, or a cache.
    pub(super) fn recover_sealed_into_overlay(&mut self, record_id: String) {
        use cockpit_proto::{Request, Response};
        let Some(binding) = self.attached_sealed_binding() else {
            self.push_plain("/sealed: attach a session first".to_string());
            return;
        };
        let operation_id = uuid::Uuid::new_v4();
        let request_binding = binding.clone();
        let pending_record_id = record_id.clone();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let worker_active = std::sync::Arc::clone(&active);
        self.start_sealed_effect(
            binding,
            PendingSealedOperation::Recover {
                operation_id,
                record_id: pending_record_id,
                active,
            },
            async move {
                // Begin and apply stay on the exact attached binding. The
                // recovered literal remains in the zeroizing response until
                // the correlated completion installs it into the reveal.
                let capability_id = match request_binding
                    .request(Request::BeginSealedOwnerOperation {
                        disposition: "recover".to_string(),
                        record_id: Some(record_id.clone()),
                        name: None,
                        description: None,
                        scope_kind: None,
                        scope_key: None,
                    })
                    .await?
                {
                    Response::SealedOwnerOperationBegun { capability_id, .. } => capability_id,
                    _ => return Err("unexpected daemon response".to_string()),
                };
                if !worker_active.load(std::sync::atomic::Ordering::Acquire) {
                    return match request_binding
                        .request(crate::tui::sealed_overlay::cancel_request(&capability_id))
                        .await
                    {
                        Ok(Response::SealedOwnerOperationCancelled { .. }) => {
                            Err("sealed recover cancelled by attachment transition".to_string())
                        }
                        _ => Err("sealed recover capability settlement failed".to_string()),
                    };
                }
                let apply = request_binding
                    .request(Request::ApplySealedOwnerOperation {
                        capability_id: capability_id.clone(),
                        literal: None,
                    })
                    .await;
                if !matches!(
                    &apply,
                    Ok(Response::SealedOwnerOperationApplied {
                        revealed_literal: Some(_)
                    })
                ) {
                    let settlement = request_binding
                        .request(crate::tui::sealed_overlay::cancel_request(&capability_id))
                        .await;
                    if !matches!(
                        settlement,
                        Ok(Response::SealedOwnerOperationCancelled { .. })
                    ) {
                        return Err("sealed recover capability settlement failed".to_string());
                    }
                }
                apply
            },
        );
    }

    pub(super) fn apply_sealed_completion(&mut self, completion: SealedCompletion) {
        use cockpit_proto::Response;
        let Some(pending) = self
            .pending_sealed_operations
            .remove(&completion.operation_id)
        else {
            return;
        };
        let binding_is_current =
            self.sealed_binding_is_current(completion.session_id, completion.attachment_epoch);
        match pending {
            PendingSealedOperation::Metadata { .. } => {
                if binding_is_current {
                    self.push_plain(crate::tui::sealed_overlay::sealed_response_text(
                        completion.response,
                    ));
                }
            }
            PendingSealedOperation::BeginWrite {
                binding,
                disposition,
                label,
                ..
            } => match completion.response {
                Ok(Response::SealedOwnerOperationBegun {
                    capability_id,
                    expires_at_ms,
                }) => {
                    self.sealed_capability_bindings
                        .insert(capability_id.clone(), binding);
                    if !matches!(self.overlay, Overlay::None) || !binding_is_current {
                        self.cancel_sealed_capability(&capability_id);
                        return;
                    }
                    self.overlay =
                        Overlay::Sealed(crate::tui::sealed_overlay::SealedOverlay::Write(
                            crate::tui::sealed_overlay::SealedWriteOverlay::new(
                                capability_id,
                                expires_at_ms,
                                disposition,
                                label,
                            ),
                        ));
                }
                Ok(_) => self.push_plain("/sealed: unexpected daemon response".to_string()),
                Err(error) => self.push_plain(format!("/sealed: {error}")),
            },
            PendingSealedOperation::ApplyWrite {
                capability_id: _capability_id,
                binding: _binding,
                summary,
                ..
            } => match completion.response {
                Ok(Response::SealedOwnerOperationApplied { .. }) if binding_is_current => {
                    let summary = summary.unwrap_or_else(|| "stored".to_string());
                    self.push_plain(format!("/sealed: {summary}"));
                }
                Ok(Response::SealedOwnerOperationApplied { .. }) => {}
                Ok(_) if binding_is_current => {
                    self.push_plain("/sealed: unexpected daemon response".to_string())
                }
                Err(error) if binding_is_current => self.push_plain(format!("/sealed: {error}")),
                Ok(_) | Err(_) => {}
            },
            PendingSealedOperation::Cancel { capability_id, .. } => match completion.response {
                Ok(Response::SealedOwnerOperationCancelled { spent: true }) => {}
                Ok(Response::SealedOwnerOperationCancelled { spent: false }) => tracing::debug!(
                    capability_id = %capability_id,
                    "sealed capability was already settled"
                ),
                Ok(_) | Err(_) if binding_is_current => self.push_plain(
                    "/sealed: capability settlement could not be confirmed".to_string(),
                ),
                Ok(_) | Err(_) => {}
            },
            PendingSealedOperation::Recover { record_id, .. } => match completion.response {
                Ok(Response::SealedOwnerOperationApplied {
                    revealed_literal: Some(literal),
                }) => {
                    if !matches!(self.overlay, Overlay::None) || !binding_is_current {
                        drop(literal);
                        return;
                    }
                    let overlay = crate::tui::sealed_overlay::SealedRevealOverlay::new(
                        record_id,
                        literal.into_zeroizing(),
                    );
                    self.overlay =
                        Overlay::Sealed(crate::tui::sealed_overlay::SealedOverlay::Reveal(overlay));
                    self.leaks_reveal_clear_pending = true;
                }
                Ok(Response::SealedOwnerOperationApplied {
                    revealed_literal: None,
                }) => self.push_plain("/sealed: recover returned no value".to_string()),
                Ok(_) => self.push_plain("/sealed: unexpected daemon response".to_string()),
                Err(error) => self.push_plain(format!("/sealed: {error}")),
            },
        }
    }
}

#[derive(Debug)]
pub(crate) struct SealedCompletion {
    pub(crate) operation_id: uuid::Uuid,
    pub(crate) session_id: uuid::Uuid,
    pub(crate) attachment_epoch: u64,
    pub(crate) response: Result<cockpit_proto::Response, String>,
}

#[derive(Debug)]
pub(super) enum PendingSealedOperation {
    Metadata {
        operation_id: uuid::Uuid,
    },
    BeginWrite {
        operation_id: uuid::Uuid,
        binding: agent_runner::AttachedRequestBinding,
        active: std::sync::Arc<std::sync::atomic::AtomicBool>,
        disposition: crate::tui::sealed_overlay::SealedWriteDisposition,
        label: String,
    },
    ApplyWrite {
        operation_id: uuid::Uuid,
        capability_id: String,
        binding: agent_runner::AttachedRequestBinding,
        summary: Option<String>,
    },
    Cancel {
        operation_id: uuid::Uuid,
        capability_id: String,
        binding: agent_runner::AttachedRequestBinding,
    },
    Recover {
        operation_id: uuid::Uuid,
        record_id: String,
        active: std::sync::Arc<std::sync::atomic::AtomicBool>,
    },
}

impl PendingSealedOperation {
    fn operation_id(&self) -> uuid::Uuid {
        match self {
            Self::Metadata { operation_id }
            | Self::BeginWrite { operation_id, .. }
            | Self::ApplyWrite { operation_id, .. }
            | Self::Cancel { operation_id, .. }
            | Self::Recover { operation_id, .. } => *operation_id,
        }
    }

    pub(super) fn invalidate(&self) {
        match self {
            Self::BeginWrite { active, .. } | Self::Recover { active, .. } => {
                active.store(false, std::sync::atomic::Ordering::Release);
            }
            Self::Metadata { .. } | Self::ApplyWrite { .. } | Self::Cancel { .. } => {}
        }
    }
}

#[cfg(test)]
mod sealed_authority_lifecycle_tests {
    use super::PendingSealedOperation;
    use std::sync::atomic::Ordering;

    #[test]
    fn attachment_transition_invalidates_unsettled_recover_before_reveal() {
        let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let pending = PendingSealedOperation::Recover {
            operation_id: uuid::Uuid::new_v4(),
            record_id: "record-a".to_string(),
            active: std::sync::Arc::clone(&active),
        };
        pending.invalidate();
        assert!(!active.load(Ordering::Acquire));
    }
}

/// Map a `/editor` argument to a pane side. Empty / unknown → fullscreen.
pub(super) fn parse_pane_side(arg: &str) -> PaneSide {
    match arg.trim().to_ascii_lowercase().as_str() {
        "left" => PaneSide::Left,
        "right" => PaneSide::Right,
        "top" | "up" => PaneSide::Top,
        "bottom" | "down" => PaneSide::Bottom,
        _ => PaneSide::Full,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SandboxCommand {
    Cycle,
    Set(cockpit_proto::SandboxMode),
    Network(bool),
}

pub(super) fn parse_sandbox_arg(args: &str) -> Result<SandboxCommand, String> {
    let normalized = args.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalized = normalized.to_ascii_lowercase();
    match normalized.as_str() {
        "" => Ok(SandboxCommand::Cycle),
        "on" => Ok(SandboxCommand::Set(cockpit_proto::SandboxMode::Sandbox)),
        "off" => Ok(SandboxCommand::Set(cockpit_proto::SandboxMode::Off)),
        "container" => Ok(SandboxCommand::Set(cockpit_proto::SandboxMode::Container)),
        "container-readonly" | "container-ro" | "readonly" => Ok(SandboxCommand::Set(
            cockpit_proto::SandboxMode::ContainerReadonly,
        )),
        "network on" => Ok(SandboxCommand::Network(true)),
        "network off" => Ok(SandboxCommand::Network(false)),
        other => Err(other.to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SandboxEscalationCommand {
    Status,
    Set(bool),
}

pub(super) fn parse_sandbox_escalation_arg(args: &str) -> Result<SandboxEscalationCommand, String> {
    let normalized = args.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalized = normalized.to_ascii_lowercase();
    match normalized.as_str() {
        "" => Ok(SandboxEscalationCommand::Status),
        "allow" | "allowed" => Ok(SandboxEscalationCommand::Set(true)),
        "disallow" | "disallowed" => Ok(SandboxEscalationCommand::Set(false)),
        other => Err(other.to_string()),
    }
}

pub(super) fn sandbox_mode_label(mode: cockpit_proto::SandboxMode) -> &'static str {
    match mode {
        cockpit_proto::SandboxMode::Off => "off",
        cockpit_proto::SandboxMode::Sandbox => "on",
        cockpit_proto::SandboxMode::Container => "container",
        cockpit_proto::SandboxMode::ContainerReadonly => "container-readonly",
    }
}

pub(super) fn next_sandbox_mode(
    current: cockpit_proto::SandboxMode,
    caps: &cockpit_proto::HostCapabilitySnapshot,
) -> cockpit_proto::SandboxMode {
    crate::tui::capability_gate::next_available_sandbox_mode(current, caps)
}

pub fn decide_sandbox_set(
    mode: cockpit_proto::SandboxMode,
    caps: &cockpit_proto::HostCapabilitySnapshot,
    refresh: impl FnOnce() -> cockpit_proto::HostCapabilitySnapshot,
) -> Result<cockpit_proto::SandboxMode, crate::tui::capability_gate::CapabilityInstruct> {
    match crate::tui::capability_gate::apply_sandbox_choice(mode, caps, refresh) {
        crate::tui::capability_gate::RecheckApply::Applied(mode) => Ok(mode),
        crate::tui::capability_gate::RecheckApply::Instruct(instruct) => Err(instruct),
    }
}

#[allow(dead_code)]
fn container_unavailable_label(
    availability: &cockpit_proto::ContainerAvailability,
) -> &'static str {
    match availability.reason {
        Some(cockpit_proto::ContainerUnavailableReason::HarnessInContainer) => {
            "Cockpit is running inside a container"
        }
        Some(cockpit_proto::ContainerUnavailableReason::PermissionDenied) => {
            "Permission denied for the container engine daemon"
        }
        Some(cockpit_proto::ContainerUnavailableReason::SocketUnavailable) => {
            "Container engine daemon socket is unavailable"
        }
        Some(cockpit_proto::ContainerUnavailableReason::DaemonUnavailable) => {
            "Container engine daemon is not running"
        }
        Some(cockpit_proto::ContainerUnavailableReason::NoRuntime) | None => {
            "No healthy docker/podman engine available"
        }
    }
}

/// Output format for `/copy`. `Markdown` keeps the raw response text
/// verbatim; `Plain` strips markdown; `Rich` copies HTML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CopyFormat {
    Markdown,
    Plain,
    Rich,
}

/// Parse the `/copy` format argument. An empty argument defaults to
/// `Markdown` (bare `/copy`). Returns `None` for an unrecognized
/// argument so the caller can show usage.
pub(super) fn parse_copy_format(arg: &str) -> Option<CopyFormat> {
    match arg.trim().to_ascii_lowercase().as_str() {
        "" | "markdown" => Some(CopyFormat::Markdown),
        "plain" | "plaintext" => Some(CopyFormat::Plain),
        "rich" | "richtext" => Some(CopyFormat::Rich),
        _ => None,
    }
}

/// Newest-first among nonempty assistant messages. `n` is 1-indexed (`1` is
/// the most recent, matching bare `/copy`); `None` behaves as `Some(1)`.
/// `Some(0)` and an `n` beyond the number of assistant messages are both
/// `None` — out of range, not an error the parser can see in isolation.
pub(super) fn select_agent_text(history: &[HistoryEntry], n: Option<usize>) -> Option<String> {
    let index = n.unwrap_or(1);
    if index == 0 {
        return None;
    }
    history
        .iter()
        .rev()
        .filter_map(|e| match e {
            HistoryEntry::Agent { text, .. } if !text.trim().is_empty() => Some(text.clone()),
            _ => None,
        })
        .nth(index - 1)
}

/// Parsed `/copy [N] [markdown|plain|rich] [file <path>]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CopyCommand {
    /// 1-indexed, newest-first among nonempty assistant messages. `None`
    /// means "the last response" (same as bare `/copy`).
    pub(super) n: Option<usize>,
    pub(super) format: CopyFormat,
    /// Present only when the `file <path>` form was used. The path is the
    /// *raw remainder* of the line after `file ` — not further tokenized,
    /// so it may contain spaces.
    pub(super) file: Option<String>,
}

/// Split off the first whitespace-delimited token, returning it and the
/// (not-yet-trimmed) remainder.
fn split_first_token(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    match s.find(char::is_whitespace) {
        Some(idx) => Some((&s[..idx], &s[idx..])),
        None => Some((s, "")),
    }
}

/// Parse the full `/copy` grammar. `"pick"` is handled by the caller before
/// this is reached (it is not part of this grammar). Every recognized
/// legacy form (`/copy`, `/copy markdown`, `/copy plain`, `/copy rich`)
/// still parses to `CopyCommand { n: None, file: None, .. }` exactly as
/// before.
pub(super) fn parse_copy_command(arg: &str) -> Result<CopyCommand, String> {
    let mut rest = arg.trim();
    let mut n = None;
    if let Some((first, tail)) = split_first_token(rest)
        && let Ok(parsed) = first.parse::<usize>()
    {
        // Positions are 1-indexed ("1" is the most recent response); `0`
        // has no meaning here and must be rejected at parse time rather
        // than accepted and only later found to have no selection —
        // `select_agent_text` already treats `Some(0)` as out of range,
        // but a parse-time rejection gives a clearer, immediate error
        // instead of "no response at position 0".
        if parsed == 0 {
            return Err("N must be 1 or greater (1 is the most recent response)".to_string());
        }
        n = Some(parsed);
        rest = tail;
    }

    let mut format = CopyFormat::Markdown;
    if let Some((first, tail)) = split_first_token(rest)
        && !first.eq_ignore_ascii_case("file")
    {
        match parse_copy_format(first) {
            Some(f) => {
                format = f;
                rest = tail;
            }
            None => {
                return Err(format!(
                    "unknown /copy argument `{first}` (expected a number, markdown/plain/rich, or `file <path>`)"
                ));
            }
        }
    }

    let mut file = None;
    if let Some((first, tail)) = split_first_token(rest) {
        if first.eq_ignore_ascii_case("file") {
            let path = tail.trim();
            if path.is_empty() {
                return Err("`/copy … file` requires a path".to_string());
            }
            file = Some(path.to_string());
            rest = "";
        } else {
            return Err(format!("unknown /copy argument `{first}`"));
        }
    }

    if !rest.trim().is_empty() {
        return Err(format!("unexpected trailing text `{}`", rest.trim()));
    }

    Ok(CopyCommand { n, format, file })
}

pub(super) fn slash_args(raw: &str) -> String {
    let rest = raw.strip_prefix('/').unwrap_or(raw);
    match rest.find(char::is_whitespace) {
        Some(idx) => rest[idx..].trim().to_string(),
        None => String::new(),
    }
}

/// The action `/mcp [args]` resolves to (GOALS §18a), separated from `App`
/// state so the subcommand parsing is unit-testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum McpAction {
    /// `/mcp` (bare) or `/mcp list`.
    List,
    /// `/mcp settings`.
    Settings,
    /// `/mcp on|off|toggle [id]`. `enable=None` toggles; `id=None` is bulk.
    SetEnabled {
        id: Option<String>,
        enable: Option<bool>,
    },
    /// Unrecognized — show usage.
    Usage,
}

/// Parse the `/mcp` argument string into an [`McpAction`]. Pure.
pub(super) fn parse_mcp_action(arg: &str) -> McpAction {
    let parts: Vec<&str> = arg.split_whitespace().collect();
    match parts.as_slice() {
        [] | ["list"] => McpAction::List,
        ["settings"] => McpAction::Settings,
        ["on", id] => McpAction::SetEnabled {
            id: Some((*id).to_string()),
            enable: Some(true),
        },
        ["on"] => McpAction::SetEnabled {
            id: None,
            enable: Some(true),
        },
        ["off", id] => McpAction::SetEnabled {
            id: Some((*id).to_string()),
            enable: Some(false),
        },
        ["off"] => McpAction::SetEnabled {
            id: None,
            enable: Some(false),
        },
        ["toggle", id] => McpAction::SetEnabled {
            id: Some((*id).to_string()),
            enable: None,
        },
        ["toggle"] => McpAction::SetEnabled {
            id: None,
            enable: None,
        },
        _ => McpAction::Usage,
    }
}

/// The decision `/agent [name]` resolves to, separated from `App` state so
/// it is unit-testable (implementation note).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AgentCommandOutcome {
    /// Switch the active primary to this (validated chat-ownable) agent.
    Switch(String),
    /// Print this line and do not switch — the bare-`/agent` listing or the
    /// unknown/non-chat-ownable error.
    Message(String),
}

/// Pure resolution of `/agent [arg]` against the chat-ownable cycle `order`
/// (builtins first, then user primaries alphabetically — see
/// the daemon inventory agent list) and the `active` agent name.
/// A blank `arg` yields the listing (active one marked `(active)`); a name in
/// `order` yields a [`AgentCommandOutcome::Switch`]; anything else yields an
/// error naming the bad value in backticks plus the valid choices. Subagents
/// and unknown names land in the error branch (they are never in `order`).
pub(super) fn agent_command_outcome(
    arg: &str,
    active: &str,
    order: &[String],
) -> AgentCommandOutcome {
    let arg = arg.trim();
    if arg.is_empty() {
        let listed = order
            .iter()
            .map(|name| {
                if name == active {
                    format!("{name} (active)")
                } else {
                    name.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        return AgentCommandOutcome::Message(format!("Available primary agents: {listed}"));
    }
    if order.iter().any(|n| n == arg) {
        AgentCommandOutcome::Switch(arg.to_string())
    } else {
        AgentCommandOutcome::Message(format!(
            "Unknown or non-chat-owning agent `{arg}` — valid choices: {}",
            order.join(", ")
        ))
    }
}

#[allow(private_interfaces)]
#[cfg(test)]
pub(super) fn slash_matches(
    query: &str,
    counts: &HashMap<String, u64>,
) -> Vec<&'static SlashCommand> {
    let _lock = super::SLASH_MENU_COUNTER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp = tempfile::tempdir().expect("slash match tempdir");
    let app = App::new(Some(tmp.path()), false);
    let available: Vec<&'static SlashCommand> = SLASH_COMMANDS
        .iter()
        .filter(|command| command.is_available(&app))
        .collect();
    slash_matches_in(&available, query, counts)
}

#[allow(private_interfaces)]
pub(super) fn slash_matches_in(
    available: &[&'static SlashCommand],
    query: &str,
    counts: &HashMap<String, u64>,
) -> Vec<&'static SlashCommand> {
    let normalized_query = slash_match_normalize(query);
    let query_is_exact_builtin = builtin_slash_name_taken(query);
    let mut matched: Vec<(usize, &'static SlashCommand)> = Vec::new();
    for (index, command) in available.iter().copied().enumerate() {
        let literal = command.name.starts_with(query);
        let hyphen_insensitive = !normalized_query.is_empty()
            && slash_match_normalize(command.name).starts_with(&normalized_query);
        let hidden_alias = !query_is_exact_builtin
            && HIDDEN_SLASH_ALIASES
                .iter()
                .any(|alias| alias.canonical == command.name && alias.alias.starts_with(query));
        if (literal || hyphen_insensitive || hidden_alias)
            && !matched.iter().any(|(_, c)| c.name == command.name)
        {
            matched.push((index, command));
        }
    }
    // Frequency tie-breaker: 30-day count desc, then the static
    // declaration order (the stable fallback) asc.
    matched.sort_by(|(ia, a), (ib, b)| {
        let ca = counts.get(a.name).copied().unwrap_or(0);
        let cb = counts.get(b.name).copied().unwrap_or(0);
        cb.cmp(&ca).then(ia.cmp(ib))
    });
    matched.into_iter().map(|(_, c)| c).collect()
}

fn slash_match_normalize(value: &str) -> String {
    value.chars().filter(|c| *c != '-').collect()
}

/// Whether `name` is claimed by a builtin slash command (including `/skill`
/// itself). A skill whose name collides is omitted from the bare-`/<name>`
/// sugar — the builtin always wins — but stays reachable via `/skill <name>`
/// (implementation note).
pub(super) fn builtin_slash_name_taken(name: &str) -> bool {
    SLASH_COMMANDS.iter().any(|c| c.name == name)
}

/// Project daemon-authorized skill summaries into bare-sugar slash-menu
/// entries, dropping any whose name collides with a builtin (the builtin keeps
/// the bare name; the skill stays reachable via `/skill <name>`).
pub(super) fn bare_skill_commands_from(
    skills: Vec<cockpit_proto::SkillSummary>,
) -> Vec<SkillCommand> {
    let mut out = Vec::with_capacity(skills.len());
    for s in skills {
        // Model-only skills (`user-invocable: false`) are hidden from the
        // user's `/` menu but still eligible for auto-injection.
        if !s.user_invocable {
            continue;
        }
        let name = s.name;
        if builtin_slash_name_taken(&name) {
            tracing::info!(
                skill = %name,
                "skill name collides with a builtin slash command; bare /{name} runs the builtin — invoke the skill via `/skill {name}`",
            );
            continue;
        }
        out.push(SkillCommand {
            name,
            description: s.description,
        });
    }
    out
}

/// Outcome of resolving a `/skill <name> [task]` dispatcher line against the
/// set of discovered skill names (implementation note).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SkillDispatch {
    /// A known skill to invoke, with any trailing task input (may be empty).
    Invoke { name: String, task: String },
    /// A helpful error line (bare `/skill` or an unknown name) — surfaced to
    /// the user, never a silent no-op.
    Error(String),
}

/// Resolve a `/skill` dispatcher argument string against the discovered skill
/// `names`. Pure (no `App`, no I/O) so the bare / unknown / known branches are
/// unit-testable. The first whitespace-delimited token is the skill name; the
/// rest is the optional task input.
pub(super) fn resolve_skill_dispatch(args: &str, names: &[&str]) -> SkillDispatch {
    let available = || {
        if names.is_empty() {
            "(none discovered)".to_string()
        } else {
            names.join(", ")
        }
    };
    let args = args.trim();
    if args.is_empty() {
        return SkillDispatch::Error(format!(
            "/skill <skill-name> [task] — invoke a skill by name. Available: {}",
            available()
        ));
    }
    let (name, task) = match args.split_once(char::is_whitespace) {
        Some((n, rest)) => (n, rest.trim()),
        None => (args, ""),
    };
    if !names.contains(&name) {
        return SkillDispatch::Error(format!(
            "/skill: unknown skill `{name}`. Available: {}",
            available()
        ));
    }
    SkillDispatch::Invoke {
        name: name.to_string(),
        task: task.to_string(),
    }
}

#[cfg(test)]
mod table_tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::collections::BTreeSet;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn setup_slash_opens_wizard_menu_and_provider() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cockpit_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit_dir).expect("create .cockpit");
        std::fs::write(cockpit_dir.join("config.json"), "{}").expect("write config");
        let cmd = *slash_command_by_name("setup").expect("/setup registry row");
        let mut app = App::new(Some(tmp.path()), false);
        app.dialog = Dialog::None;

        app.composer.set("/setup".to_string());
        app.execute_slash(cmd);
        assert_eq!(app.dialog.test_page_name(), Some("wizard_menu"));

        app.dialog = Dialog::None;
        app.composer.set("/setup provider".to_string());
        app.execute_slash(cmd);
        assert_eq!(app.dialog.test_page_name(), Some("Providers"));
        assert_eq!(app.dialog.test_provider_surface(), Some("other"));

        app.dialog = Dialog::None;
        app.composer.set("/setup security".to_string());
        app.execute_slash(cmd);
        assert_eq!(app.dialog.test_page_name(), Some("security"));
    }

    #[test]
    fn favorite_uses_daemon_confirmed_session_model_not_stale_default() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut app = App::new(Some(tmp.path()), false);
        app.dialog = Dialog::None;
        app.config_snapshot.providers.providers.insert(
            "p".to_string(),
            cockpit_config::providers::ProviderEntry {
                models: vec![cockpit_config::providers::ModelEntry {
                    id: "a".to_string(),
                    favorite: false,
                    ..Default::default()
                }],
                ..Default::default()
            },
        );
        app.config_snapshot.providers.active_model =
            Some(cockpit_config::providers::ActiveModelRef {
                provider: "provider-b".to_string(),
                model: "stale".to_string(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            });
        app.active_model_selection = Some(cockpit_config::providers::ActiveModelRef {
            provider: "p".to_string(),
            model: "a".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        });
        let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(4);
        app.agent_runner = Some(Ok(
            crate::tui::agent_runner::AgentRunner::stub_with_control_tx(control_tx),
        ));

        run_favorite(&mut app, "");

        assert!(matches!(
            control_rx.try_recv().expect("favorite request").request,
            cockpit_proto::Request::SetModelFavorite {
                provider,
                model,
                favorite: true,
            } if provider == "p" && model == "a"
        ));
        assert!(
            !app.history.iter().any(
                |entry| matches!(entry, HistoryEntry::Plain { line } if line.contains("marked"))
            ),
            "success must wait for daemon acknowledgement"
        );
    }

    #[test]
    fn help_command_registered() {
        let help = slash_command_by_name("help").expect("/help registry row");

        assert!(!help.takes_args);
        assert!(std::ptr::fn_addr_eq(
            help.run,
            run_help as fn(&mut App, &str) -> bool
        ));
        assert_eq!(
            hidden_slash_alias("?").expect("/? hidden alias").name,
            "help"
        );
    }

    #[test]
    fn help_overlay_opens_and_closes() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cmd = *slash_command_by_name("help").expect("/help registry row");
        let mut app = App::new(Some(tmp.path()), false);
        app.dialog = Dialog::None;
        app.question_dialog = None;

        app.composer.set("/help".to_string());
        app.execute_slash(cmd);
        assert!(matches!(app.overlay, Overlay::Help(_)));

        assert!(!app.handle_key(press(KeyCode::Esc)));
        assert!(matches!(app.overlay, Overlay::None));

        let alias = hidden_slash_alias("?").expect("/? hidden alias");
        app.composer.set("/?".to_string());
        app.execute_slash(alias);
        assert!(matches!(app.overlay, Overlay::Help(_)));
    }

    #[test]
    fn learn_slash_is_registered_as_arg_taking_normal_turn() {
        let learn = slash_command_by_name("learn").expect("/learn registry row");
        assert!(learn.takes_args);
        assert!(std::ptr::fn_addr_eq(
            learn.run,
            run_learn as fn(&mut App, &str) -> bool
        ));
        assert!(builtin_slash_name_taken("learn"));
    }

    #[test]
    fn every_row_dispatches_and_every_alias_resolves() {
        for command in SLASH_COMMANDS {
            assert!(
                !command.name.is_empty(),
                "slash command names are non-empty"
            );
            let _dispatch: fn(&mut App, &str) -> bool = command.run;
            let _available: fn(&App) -> bool = command.available;
            let _describe: fn(&App, &SlashCommand) -> String = command.describe;
        }

        for alias in HIDDEN_SLASH_ALIASES {
            let command = hidden_slash_alias(alias.alias)
                .unwrap_or_else(|| panic!("alias {} must resolve", alias.alias));
            assert_eq!(command.name, alias.canonical, "alias {}", alias.alias);
        }
    }

    #[test]
    fn help_copy_no_internal_jargon_in_slash_descriptions() {
        for command in SLASH_COMMANDS {
            for needle in ["GOALS", "§", "design notes", "repair catalog", "ralph"] {
                assert!(
                    !command.description.contains(needle),
                    "/{} description contains internal jargon `{needle}`: {}",
                    command.name,
                    command.description
                );
            }
        }
    }

    #[test]
    fn adding_a_slash_command_is_one_row() {
        let mut names = BTreeSet::new();
        for command in SLASH_COMMANDS {
            assert!(
                names.insert(command.name),
                "duplicate /{} row",
                command.name
            );
            assert_eq!(
                slash_command_by_name(command.name).map(|found| found.name),
                Some(command.name),
                "/{} should be discoverable from the registry row",
                command.name
            );
        }
        assert_eq!(names.len(), SLASH_COMMANDS.len());
        assert!(
            names.contains("setup"),
            "wizard /setup must remain registered"
        );
        assert!(
            names.contains("session-setup"),
            "session setup pane must be /session-setup, not a second /setup"
        );

        for alias in HIDDEN_SLASH_ALIASES {
            assert!(
                slash_command_by_name(alias.canonical).is_some(),
                "alias {} must point at a registry row",
                alias.alias
            );
            assert!(
                !names.contains(alias.alias),
                "alias {} must stay hidden, not a second row",
                alias.alias
            );
        }
    }

    #[test]
    fn sealed_slash_command_is_owner_remoted() {
        // The legacy session-scoped `/sealed` list/delete path (with its
        // `ListSealedValues`/`DeleteSealedValue` wire tags) is gone; `/sealed` is
        // now the owner-remoted frontend over `parse_sealed_command` — registered
        // again, but routing only sealed-owner RPCs.
        assert!(slash_command_by_name("sealed").is_some());
    }

    fn leak_report_row(
        id: &str,
        plan: Option<cockpit_proto::LeakRotationPlan>,
    ) -> cockpit_proto::LeakReportMetadata {
        cockpit_proto::LeakReportMetadata {
            report_id: id.to_string(),
            session_id: uuid::Uuid::nil(),
            source: "provider".to_string(),
            category: "api_key".to_string(),
            provider_id: None,
            model_id: None,
            generation: None,
            connector_id: None,
            status: "contained".to_string(),
            rotation: "pending".to_string(),
            rotation_plan: plan,
            seen_count: 3,
            first_reported_ms: 100,
            last_reported_ms: 200,
            contained_at_ms: None,
        }
    }

    #[test]
    fn leaks_request_parses_list_rotate_delete_variants() {
        use cockpit_proto::{LeakRotationDisposition, Request};
        for input in ["", "  ", "list"] {
            assert!(
                matches!(
                    leaks_request(input),
                    Some(Request::ListLeakReports {
                        cursor: None,
                        limit: None,
                        project_root: None,
                        session_id: None,
                        rotation: None,
                    })
                ),
                "expected list variant for {input:?}"
            );
        }
        for (input, expected) in [
            ("rotate r1 accept", LeakRotationDisposition::Accept),
            ("rotate r1 dismiss", LeakRotationDisposition::Dismiss),
            ("rotate r1 rotated", LeakRotationDisposition::Rotated),
        ] {
            match leaks_request(input) {
                Some(Request::MarkLeakRotated {
                    report_id,
                    rotation,
                }) => {
                    assert_eq!(report_id, "r1");
                    assert_eq!(rotation, expected);
                }
                other => panic!("expected MarkLeakRotated for {input:?}, got {other:?}"),
            }
        }
        match leaks_request("delete r1") {
            Some(Request::DeleteLeakReport { report_id }) => assert_eq!(report_id, "r1"),
            other => panic!("expected DeleteLeakReport for `delete r1`, got {other:?}"),
        }
        for input in [
            "rotate",
            "rotate r1",
            "rotate r1 bogus",
            "delete",
            "nonsense",
        ] {
            assert!(
                leaks_request(input).is_none(),
                "expected None for {input:?}"
            );
        }
    }

    #[test]
    fn leaks_registry_row_is_registered() {
        let row = slash_command_by_name("leaks").expect("/leaks registry row");
        assert!(row.takes_args);
    }

    #[test]
    fn leaks_response_text_maps_known_variants_and_hides_unexpected_debug() {
        use cockpit_proto::{LeakReportsPage, Response};
        let page = LeakReportsPage {
            reports: vec![leak_report_row("rpt-a", None)],
            next_cursor: None,
            has_more: false,
        };
        // (a) list response equals the pure formatter output.
        assert_eq!(
            leak_response_text(Ok(Response::LeakReports { page: page.clone() })),
            format_leak_reports(&page)
        );
        // (b) rotation updated.
        assert_eq!(
            leak_response_text(Ok(Response::LeakRotationUpdated {
                report_id: "rpt-a".to_string(),
                rotation: "rotated".to_string(),
            })),
            "/leaks: rotated rpt-a -> rotated"
        );
        // (c) deleted.
        assert_eq!(
            leak_response_text(Ok(Response::LeakReportDeleted {
                report_id: "rpt-a".to_string(),
            })),
            "/leaks: deleted protected value for rpt-a; safe metadata retained"
        );
        // (d) typed daemon/auth failure folded to Err(String) by request_ok.
        assert_eq!(
            leak_response_text(Err("daemon error: unauthorized".to_string())),
            "/leaks: daemon error: unauthorized"
        );
        // (e) unrelated success variant -> fixed line, no Debug payload.
        let unexpected = leak_response_text(Ok(Response::Ack));
        assert_eq!(unexpected, "/leaks: unexpected response");
        assert!(!unexpected.contains("Ack"));
        // (f) transport-style error surfaces prefixed.
        let transport = leak_response_text(Err("connect: broken pipe".to_string()));
        assert!(transport.starts_with("/leaks: "));
        assert!(transport.contains("connect: broken pipe"));
    }

    #[test]
    fn leaks_format_reports_renders_empty_rows_and_has_more() {
        use cockpit_proto::LeakReportsPage;
        let empty = LeakReportsPage {
            reports: vec![],
            next_cursor: None,
            has_more: false,
        };
        assert_eq!(
            format_leak_reports(&empty),
            "/leaks: no contained leak reports"
        );

        let two = LeakReportsPage {
            reports: vec![
                leak_report_row("rpt-a", None),
                leak_report_row("rpt-b", None),
            ],
            next_cursor: None,
            has_more: false,
        };
        let rendered = format_leak_reports(&two);
        assert!(rendered.contains(
            "report_id | source | category | status | rotation | rotation_plan | seen_count | last_reported_ms"
        ));
        assert!(rendered.contains("rpt-a"));
        assert!(rendered.contains("rpt-b"));
        assert!(!rendered.contains("more reports available"));

        let more = LeakReportsPage {
            reports: vec![leak_report_row("rpt-a", None)],
            next_cursor: Some("cursor".to_string()),
            has_more: true,
        };
        assert!(format_leak_reports(&more).contains("more reports available"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use tokio::sync::mpsc;

    use crate::tui::agent_runner::{AgentRunner, AttachedRequest, TestRunnerOverrides};
    use crate::tui::history::HistoryEntry;
    use cockpit_proto::{GoalDisposition, GoalSummary, Request, Response};

    fn app_with_attached_request_rx() -> (App, mpsc::Receiver<AttachedRequest>) {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.dialog = crate::tui::settings::Dialog::None;
        let (attached_request_tx, attached_request_rx) = mpsc::channel::<AttachedRequest>(8);
        let runner = AgentRunner::test_fixture(TestRunnerOverrides {
            attached_request_tx: Some(attached_request_tx),
            short_id: Some("goal01".to_string()),
            socket: Some(PathBuf::from("/tmp/cockpit-goal-test.sock")),
            ..Default::default()
        });
        app.agent_runner = Some(Ok(runner));
        (app, attached_request_rx)
    }

    fn goal_summary(disposition: GoalDisposition) -> GoalSummary {
        GoalSummary {
            id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            project_id: "project".to_string(),
            objective: "ship it".to_string(),
            context: None,
            disposition,
            phase: (disposition == GoalDisposition::Running)
                .then_some(cockpit_proto::GoalPhase::Executing),
            resume_phase: None,
            pause_reason: (disposition == GoalDisposition::UserPaused)
                .then_some(cockpit_proto::GoalPauseReason::User),
            contract_available: true,
            latest_gap_or_blocker: None,
            verification_attempts: 2,
            max_verification_attempts: 4,
            attempt_generation: 1,
            token_budget: 100,
            tokens_used: 4,
            remaining_tokens: 96,
            elapsed_active_ms: 1_250,
            lifecycle_history: vec![cockpit_proto::GoalLifecycleHistoryEntry {
                at: 0,
                disposition,
                phase: None,
                reason: None,
            }],
            blocked_attempts: 0,
            last_read_at: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn goal_budget_parser_rejects_missing_malformed_nonpositive_and_duplicate_values() {
        for input in [
            "--budget ship",
            "--budget nope ship",
            "--budget 0 ship",
            "--budget -4 ship",
            "--budget 4 --budget 5 ship",
        ] {
            assert!(App::parse_goal_create_args(input).is_err(), "{input}");
        }
        assert_eq!(
            App::parse_goal_create_args("--budget 42 ship the feature").unwrap(),
            (Some(42), "ship the feature".to_string())
        );
    }

    async fn answer_goal_request(
        app: &mut App,
        rx: &mut mpsc::Receiver<AttachedRequest>,
        response: Result<Response, String>,
    ) -> Request {
        let request = rx.recv().await.expect("goal daemon request");
        let observed = request.request.clone();
        request
            .response_tx
            .send(response)
            .expect("deliver goal response");
        for _ in 0..20 {
            if app.drain_async_actions() {
                break;
            }
            tokio::task::yield_now().await;
        }
        observed
    }

    fn history_lines(app: &App) -> Vec<&str> {
        app.history
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::Plain { line } | HistoryEntry::CommandError { line } => {
                    Some(line.as_str())
                }
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn goal_status_renders_lifecycle_snapshot() {
        let (mut app, mut rx) = app_with_attached_request_rx();
        let command = *slash_command_by_name("goal").expect("/goal command");
        let cases = [
            ("/goal", Response::GoalStatus { goal: None }),
            (
                "/goal status",
                Response::GoalStatus {
                    goal: Some(goal_summary(GoalDisposition::Running)),
                },
            ),
            (
                "/goal status",
                Response::GoalStatus {
                    goal: Some(goal_summary(GoalDisposition::UserPaused)),
                },
            ),
            (
                "/goal pause",
                Response::GoalUpdated {
                    goal: goal_summary(GoalDisposition::UserPaused),
                },
            ),
            (
                "/goal resume",
                Response::GoalUpdated {
                    goal: goal_summary(GoalDisposition::Running),
                },
            ),
            ("/goal clear", Response::GoalCleared { cleared: true }),
        ];
        for (input, response) in cases {
            app.composer.set(input.to_string());
            app.execute_slash(command);
            answer_goal_request(&mut app, &mut rx, Ok(response)).await;
        }
        let lines = history_lines(&app);
        assert!(lines.iter().any(|line| line.contains("no goal")));
        assert!(lines.iter().any(|line| line.contains("tokens 4/100")));
        assert!(lines.iter().any(|line| line.contains("active 1250ms")));
        assert!(lines.iter().any(|line| line.contains("1 transitions")));
        assert!(lines.iter().any(|line| line.contains("pause none")));
        assert!(lines.iter().any(|line| line.contains("pause user")));
        assert!(lines.iter().any(|line| line.contains("verification 2/4")));
        assert!(lines.iter().any(|line| line.contains("goal is now paused")));
        assert!(lines.iter().any(|line| line.contains("goal is now active")));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("cleared current goal"))
        );
    }

    #[tokio::test]
    async fn goal_controls_cover_every_open_disposition() {
        let (mut app, mut rx) = app_with_attached_request_rx();
        let command = *slash_command_by_name("goal").expect("/goal command");
        for disposition in [
            GoalDisposition::Running,
            GoalDisposition::UserPaused,
            GoalDisposition::BudgetLimited,
            GoalDisposition::Blocked,
            GoalDisposition::InfraPaused,
            GoalDisposition::NoProgressPaused,
        ] {
            app.composer.set("/goal clear".to_string());
            app.execute_slash(command);
            let request = answer_goal_request(
                &mut app,
                &mut rx,
                Ok(Response::GoalCleared { cleared: true }),
            )
            .await;
            assert!(matches!(request, Request::ClearGoal { .. }));
            assert!(disposition.is_open());
        }
    }

    #[tokio::test]
    async fn goal_db_error_renders_message() {
        let (mut app, mut rx) = app_with_attached_request_rx();
        let command = *slash_command_by_name("goal").expect("/goal command");
        app.composer.set("/goal status".to_string());
        app.execute_slash(command);
        answer_goal_request(&mut app, &mut rx, Err("database unavailable".to_string())).await;
        assert!(
            history_lines(&app)
                .iter()
                .any(|line| line.contains("/goal: database unavailable"))
        );
    }

    #[tokio::test]
    async fn goal_write_uses_daemon_when_available() {
        let (mut app, mut rx) = app_with_attached_request_rx();
        let command = *slash_command_by_name("goal").expect("/goal command");
        app.composer.set("/goal pause".to_string());
        app.execute_slash(command);
        let request = answer_goal_request(
            &mut app,
            &mut rx,
            Ok(Response::GoalUpdated {
                goal: goal_summary(GoalDisposition::UserPaused),
            }),
        )
        .await;
        assert!(matches!(
            request,
            Request::SetGoalStatus {
                status: GoalDisposition::UserPaused,
                ..
            }
        ));
    }

    #[test]
    fn runtime_hostile_db_helpers_are_banned_from_tui_source() {
        fn visit(dir: &std::path::Path, violations: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read TUI source") {
                let path = entry.expect("source entry").path();
                if path.is_dir() {
                    visit(&path, violations);
                } else if path.extension().is_some_and(|extension| extension == "rs")
                    && std::fs::read_to_string(&path)
                        .expect("read TUI Rust source")
                        .contains(concat!("blocking_for_", "sync_cli"))
                {
                    violations.push(path);
                }
            }
        }
        let mut violations = Vec::new();
        visit(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut violations,
        );
        assert!(
            violations.is_empty(),
            "TUI code must use async DB access or the daemon, not blocking_for_ sync_cli: {violations:?}"
        );
    }
}
