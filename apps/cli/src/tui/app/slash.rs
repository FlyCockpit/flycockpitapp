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

fn describe_trusted_only(app: &App, _: &SlashCommand) -> String {
    format!(
        "{} Require trusted models for every inference (arg: on/off/default on/default off; bare = toggle)",
        on_off(app.trusted_only_enabled)
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

fn describe_llm_mode(app: &App, _: &SlashCommand) -> String {
    format!(
        "LLM steering mode is `{}` (arg: toggle/defend/normal; bare = toggle)",
        app.llm_mode.as_str()
    )
}

fn describe_mouse(app: &App, _: &SlashCommand) -> String {
    format!(
        "{} Toggle mouse capture (click-to-position, drag-select) on/off",
        on_off(app.mouse_capture)
    )
}

fn describe_mcp(app: &App, _: &SlashCommand) -> String {
    let cfg = app.mcp_load();
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
        name: "build",
        description: "Switch the primary agent to Build (make changes)",
        takes_args: false,
        run: run_build,
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
        name: "llm-mode",
        description: "Switch LLM steering mode (arg: toggle/defend/normal; bare = toggle)",
        takes_args: true,
        run: run_llm_mode,
        available: available_always,
        describe: describe_llm_mode,
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
        description: "Switch the active model",
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
        name: "permissions",
        description: "View and delete persisted command/path approvals across project and global scopes",
        takes_args: false,
        run: run_permissions,
        available: available_always,
        describe: describe_static,
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
        description: "Show resource scheduler state (arg: promote <request-id>)",
        takes_args: true,
        run: run_resources,
        available: available_always,
        describe: describe_static,
    },
    SlashCommand {
        name: "trusted-only",
        description: "Require trusted models for every inference (arg: on/off/default on/default off; bare = toggle)",
        takes_args: true,
        run: run_trusted_only,
        available: available_always,
        describe: describe_trusted_only,
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
        name: "swarm",
        description: "Switch the primary agent to Swarm (recursive parallel fan-out; burns lots of tokens)",
        takes_args: false,
        run: run_swarm,
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
        description: "Open the settings dialog",
        takes_args: false,
        run: run_settings,
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

fn run_exit(_: &mut App, _: &str) -> bool {
    true
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
    match crate::tui::model_picker::toggle_active_favorite(&app.launch.cwd) {
        Ok((new, p, m)) => {
            let verb = if new { "marked" } else { "unmarked" };
            app.history.push(HistoryEntry::Plain {
                line: format!("/favorite: {verb} {p}/{m} as favorite"),
            });
            app.reload_launch_info();
        }
        Err(e) => app.history.push(HistoryEntry::Plain {
            line: format!("/favorite: {e}"),
        }),
    }
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

fn run_llm_mode(app: &mut App, args: &str) -> bool {
    app.handle_llm_mode_command(args);
    false
}

fn run_init(app: &mut App, args: &str) -> bool {
    app.handle_init_command(args);
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

fn run_quick(app: &mut App, _: &str) -> bool {
    app.open_quick_dialog();
    false
}

fn run_trusted_only(app: &mut App, args: &str) -> bool {
    app.handle_trusted_only_command(args);
    false
}

fn run_stats(app: &mut App, _: &str) -> bool {
    app.overlay = Overlay::Stats(crate::tui::stats_pane::StatsPane::open(&app.launch.cwd));
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
    app.overlay = Overlay::Diff(crate::tui::diff_pane::DiffPane::open(
        source,
        &app.launch.cwd,
        &app.history,
        app.diff_style,
    ));
    false
}

fn run_sessions(app: &mut App, _: &str) -> bool {
    let daemon_socket = app
        .sessions_daemon_socket()
        .map(std::path::Path::to_path_buf);
    app.overlay = Overlay::Sessions(crate::tui::sessions_pane::SessionsPane::open(
        &app.launch.cwd,
        app.daemon_connected,
        daemon_socket,
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

fn run_skills(app: &mut App, _: &str) -> bool {
    app.overlay = Overlay::Skills(crate::tui::skills_pane::SkillsPane::open(&app.launch.cwd));
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

fn run_agent(app: &mut App, args: &str) -> bool {
    app.handle_agent_command(args);
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

fn run_swarm(app: &mut App, _: &str) -> bool {
    app.swap_primary_agent("Swarm");
    false
}

fn run_permissions(app: &mut App, _: &str) -> bool {
    app.overlay = Overlay::Permissions(crate::tui::permissions_pane::PermissionsPane::open(
        &app.launch.cwd,
    ));
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
        self.composer.clear();
        self.paste_registry.clear();
        self.reset_slash_window();
        self.record_usage(
            crate::daemon::proto::UsageKind::Slash,
            cmd.name.to_string(),
            None,
        );
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
                self.start_resource_promote_action(request_id.to_string());
            }
            _ => {
                self.push_plain(
                    "/resources: usage `/resources` or `/resources promote <request-id>`"
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
        let target = crate::commands::init::resolve_target(&self.launch.cwd, explicit);
        let display = crate::commands::init::display_target(&self.launch.cwd, &target);

        if target.exists() {
            // Existing target: ask update / overwrite / cancel via the
            // shared question dialog, driven locally (no daemon interrupt).
            use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
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
        let prompt = crate::commands::init::build_init_prompt(
            &display,
            crate::commands::init::InitMode::Create,
        );
        self.dispatch_init_turn(&display, prompt);
    }

    fn handle_goal_command(&mut self, args: &str) {
        let trimmed = args.trim();
        if trimmed.is_empty() || trimmed == "status" {
            self.show_goal_status();
            return;
        }
        match trimmed {
            "pause" => {
                self.set_goal_status(crate::db::session_goals::GoalStatus::Paused, "/goal pause");
            }
            "resume" => {
                self.set_goal_status(crate::db::session_goals::GoalStatus::Active, "/goal resume");
            }
            "clear" => {
                let Some(session_id) = self.launch.session_id else {
                    self.push_plain("/goal clear: no active session.".to_string());
                    return;
                };
                match crate::db::Db::open_default().and_then(|db| db.clear_session_goal(session_id))
                {
                    Ok(true) => self.push_plain("/goal clear: cleared current goal.".to_string()),
                    Ok(false) => self.push_plain("/goal clear: no open goal.".to_string()),
                    Err(e) => self.history.push(HistoryEntry::CommandError {
                        line: format!("/goal clear: {e:#}"),
                    }),
                }
            }
            "edit" => {
                self.composer.set("/goal ".to_string());
                self.push_plain(
                    "/goal edit: update the objective in the composer and submit.".to_string(),
                );
            }
            _ => {
                self.swap_primary_agent("Build");
                let wire = build_goal_clarification_prompt(trimmed);
                self.dispatch_goal_turn(trimmed, wire);
            }
        }
    }

    /// `/skill <skill-name> [task]` — the universal dispatcher
    /// (implementation note). Invokes ANY discovered skill
    /// by name, including ones shadowed from the bare-`/<name>` sugar by a
    /// builtin collision. Bare `/skill` (no name) or an unknown name lists the
    /// available skills as a clear error — never a silent no-op. Trailing text
    /// after the name is forwarded as the accompanying task input.
    pub(super) fn handle_skill_command(&mut self, args: &str) {
        // Re-discover per call so the dispatcher sees colliding +
        // freshly-added skills regardless of the startup `skill_commands`
        // cache (which holds only the non-colliding bare entries).
        let skills = self.visible_skills();
        let names: Vec<&str> = skills.iter().map(|s| s.frontmatter.name.as_str()).collect();
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
    /// run on the user's dime). Cancellation rides the same fire-and-forget
    /// request channel the autocomplete tally uses.
    pub(super) fn handle_schedule_command(&mut self, args: &str) {
        let args = args.trim();
        if let Some(rest) = args.strip_prefix("cancel") {
            let job_id = rest.trim();
            if job_id.is_empty() {
                self.push_plain("/schedule: usage `/schedule cancel <id>`".to_string());
                return;
            }
            let sent = match self.agent_runner.as_ref() {
                Some(Ok(runner)) => runner
                    .record_tx
                    .try_send(crate::daemon::proto::Request::CancelSchedule {
                        job_id: job_id.to_string(),
                    })
                    .is_ok(),
                _ => false,
            };
            let line = if sent {
                format!("/schedule: cancel requested for `{job_id}`")
            } else {
                format!("/schedule: no daemon connection — cannot cancel `{job_id}`")
            };
            self.push_plain(line);
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

    /// `/plan` / `/build` — swap the session's primary agent (`plan.md
    /// §4.6.d`). Sends `SetAgent`, which the worker persists and forwards to
    /// the driver as a live root-frame swap at the idle boundary; the chrome
    /// updates off the daemon's `PrimarySwapped` event. A no-op message when
    /// no runner is connected yet.
    /// `/llm-mode [toggle|defend|defensive|normal|frontier]` — switch the
    /// active LLM-strength steering mode live. No argument or `toggle` cycles
    /// `defensive → normal → frontier → defensive`; `defend` (advertised,
    /// shorter to type) and its silent alias `defensive` select defensive;
    /// `normal` and `frontier` select those modes. Switching busts the cached
    /// system prefix, so we surface the shared cache-break warning (suppressed
    /// on a no-cache provider). The actual rebuild happens daemon-side; the
    /// `LlmModeChanged` event confirms it.
    pub(super) fn handle_llm_mode_command(&mut self, arg: &str) {
        let requested = match parse_llm_mode_arg(arg) {
            Ok(r) => r,
            Err(usage) => {
                self.push_plain(usage);
                return;
            }
        };
        // Resolve the target (for the no-op check + warning), against the
        // tracked authoritative value. The daemon re-resolves a toggle too,
        // so a stale client value can't desync the outcome.
        let target = requested.unwrap_or_else(|| self.llm_mode.cycled());
        if target == self.llm_mode {
            self.push_plain(format!("Already in `{}` LLM mode", target.as_str()));
            return;
        }
        let sent =
            self.send_daemon_request(crate::daemon::proto::Request::SetLlmMode { mode: requested });
        if !sent {
            self.push_plain(
                "Send a message first to start a session, then switch LLM mode".to_string(),
            );
            return;
        }
        // Cache-break warning via the shared helper (silent on no-cache).
        if let Some(warning) = self.cache_break_warning() {
            self.push_plain(warning);
        }
        // The `LlmModeChanged` event pushes the "Switched to …" confirmation
        // once the daemon applies it.
    }

    /// Handle `/mcp …` (GOALS §18a). Operates directly on the layered
    /// `mcp.json` (server config is not daemon state); pushes result lines
    /// into history.
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
    /// (builtins `Auto`/`Plan`/`Build`/`Swarm` + user-defined
    /// `primary`/`all`) and
    /// route a valid one through [`Self::swap_primary_agent`] (same
    /// confirmation line + start-a-session-first guard `/plan`/`/build`
    /// have); an unknown or subagent-only name prints an error naming the
    /// bad value in backticks plus the valid choices and does **not** switch.
    /// Bare `/agent` lists the primaries, marking the active one — it does
    /// not switch and does not open a picker.
    pub(super) fn handle_agent_command(&mut self, arg: &str) {
        let order = crate::agents::chat_ownable_primaries(&self.launch.cwd);
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
                    &self.container_availability,
                )),
                None,
            ),
            SandboxCommand::Set(mode) => {
                if mode.is_container() && !self.container_availability.available {
                    self.push_plain(format!(
                        "/sandbox: container modes unavailable: {}",
                        container_unavailable_label(&self.container_availability)
                    ));
                    return;
                }
                (Some(mode), None)
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
        if !self.send_daemon_request(crate::daemon::proto::Request::SetSandbox {
            mode,
            container_network_enabled: network,
        }) {
            self.push_plain("/sandbox: no daemon connection".to_string());
        }
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
                if !self.send_daemon_request(crate::daemon::proto::Request::SetSandboxEscalation {
                    enabled,
                }) {
                    self.push_plain("/sandbox-escalate: no daemon connection".to_string());
                }
            }
            Err(other) => {
                self.push_plain(format!(
                    "/sandbox-escalate: unknown arg `{other}` - use allow, disallow, or no arg for status"
                ));
            }
        }
    }

    pub(super) fn handle_doctor_command(&mut self) {
        let input = crate::diagnostics::DiagnosticsInput {
            cwd: self.launch.cwd.clone(),
            session_id: self.launch.session_id,
            session_short_id: self.launch.session_short_id.clone(),
            active_agent: self.launch.agent_name.clone(),
            active_model: self.launch.active_model.clone(),
            sandbox_enabled: Some(!self.no_sandbox),
        };
        match crate::diagnostics::tui_snapshot(input) {
            Ok(snapshot) => self.push_plain(crate::diagnostics::render(&snapshot)),
            Err(error) => self.push_plain(format!("/doctor: {error}")),
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
        if !self.send_daemon_request(crate::daemon::proto::Request::SetPreflight { enabled }) {
            self.push_plain("/preflight: no daemon connection".to_string());
        }
    }

    /// `/trusted-only [on|off|default on|default off]`: require trusted
    /// provider/model targets for subsequent inference requests. A bare
    /// invocation toggles the live session state. `default on/off` persists the
    /// default and applies it to the current session.
    pub(super) fn handle_trusted_only_command(&mut self, args: &str) {
        let normalized = args.trim().to_ascii_lowercase();
        let mut persist_default = false;
        let enabled = match normalized.as_str() {
            "" => None,
            "on" | "enable" | "enabled" => Some(true),
            "off" | "disable" | "disabled" => Some(false),
            "default on" | "persist on" => {
                persist_default = true;
                Some(true)
            }
            "default off" | "persist off" => {
                persist_default = true;
                Some(false)
            }
            other => {
                self.push_plain(format!(
                        "/trusted-only: unknown arg `{other}` — use `on`, `off`, `default on`, `default off`, or no arg to toggle"
                    ));
                return;
            }
        };
        if persist_default
            && let Some(value) = enabled
            && let Err(error) = persist_trusted_only_default(&self.launch.cwd, value)
        {
            self.push_plain(format!(
                "/trusted-only: failed to persist default: {error:#}"
            ));
            return;
        }
        if !self.send_daemon_request(crate::daemon::proto::Request::SetTrustedOnly { enabled }) {
            self.push_plain("/trusted-only: no daemon connection".to_string());
        }
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
        let mode = match crate::daemon::caffeinate::CaffeinateMode::parse(args) {
            Ok(m) => m,
            Err(other) => {
                self.push_plain(format!(
                        "/caffeinate: unknown arg `{other}` — use `on`, `off`, `until-idle`, or no arg to toggle"
                    ));
                return;
            }
        };
        if !self.send_daemon_request(crate::daemon::proto::Request::SetCaffeinate { mode }) {
            self.push_plain("/caffeinate: no daemon connection".to_string());
        }
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
        if self.send_daemon_request(crate::daemon::proto::Request::Pin {
            text: text.to_string(),
        }) {
            self.push_plain(format!(
                "/pin-context: pinned (survives /compact verbatim): {text}"
            ));
        } else {
            self.push_plain("/pin-context: no daemon connection — cannot pin.".to_string());
        }
    }

    /// `/copy [format]` — copy the last assistant response (message text,
    /// excluding tool-call chrome) to the system clipboard. Default
    /// format is `markdown` (the raw response verbatim); `plain` strips
    /// the markdown; `rich` copies HTML. Mirrors the context-menu copy
    /// path (`execute_context_menu_action`) and reuses the clipboard
    /// module. Surfaces feedback via a toast.
    pub(super) fn handle_copy_command(&mut self, arg: &str) {
        if arg.trim().eq_ignore_ascii_case("pick") {
            self.enter_copy_pick_mode();
            return;
        }
        let format = match parse_copy_format(arg) {
            Some(f) => f,
            None => {
                self.show_toast(
                    "Usage: `/copy [markdown|plain|rich]` (markdown is the default)",
                    ToastKind::Info,
                );
                return;
            }
        };
        let Some(text) = last_agent_text(&self.history) else {
            self.show_toast("No response to copy yet.", ToastKind::Info);
            return;
        };
        let (msg, kind) = match format {
            CopyFormat::Markdown => match crate::clipboard::copy_plain(&text) {
                Ok(_) => (
                    "Copied last response (markdown).".to_string(),
                    ToastKind::Success,
                ),
                Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
            },
            CopyFormat::Plain => {
                let plain = crate::clipboard::markdown_to_plain(&text);
                match crate::clipboard::copy_plain(&plain) {
                    Ok(_) => (
                        "Copied last response (plain).".to_string(),
                        ToastKind::Success,
                    ),
                    Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
            CopyFormat::Rich => {
                let html = crate::clipboard::markdown_to_html(&text);
                match crate::clipboard::copy_rich(&text, &html) {
                    Ok(_) => (
                        "Copied last response (rich).".to_string(),
                        ToastKind::Success,
                    ),
                    Err(crate::clipboard::CopyError::UnsupportedOverSsh) => {
                        // No multi-format clipboard pathway over SSH —
                        // fall back to plain so `/copy rich` never
                        // silently does nothing, and say why.
                        match crate::clipboard::copy_plain(&text) {
                            Ok(_) => (
                                "SSH — copied last response as plain text \
                                 (rich copy unavailable over SSH)."
                                    .to_string(),
                                ToastKind::Success,
                            ),
                            Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                        }
                    }
                    Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
        };
        self.show_toast(msg, kind);
    }

    /// `/rename <title>` manually renames the current session. `/rename`
    /// without a title asks the utility model to generate a fresh auto title
    /// from the durable user-authored transcript.
    pub(super) fn handle_rename_command(&mut self, arg: &str) {
        let title = arg.trim();
        // Authoritative current session: the live runner if attached,
        // else the last-attached id tracked on launch info.
        let session_id = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => Some(runner.session_id),
            _ => self.launch.session_id,
        };
        let Some(session_id) = session_id else {
            self.push_plain("/rename: no active session yet — send a message first".to_string());
            return;
        };
        if title.is_empty() {
            self.push_plain("/rename: generating".to_string());
            self.async_actions.start(
                AsyncActionKind::Internal("rename.auto"),
                AsyncActionPolicy::AllowConcurrent,
                async move {
                    let db = crate::db::Db::open_default().map_err(|e| e.to_string())?;
                    let session = crate::session::Session::resume(db, session_id)
                        .map_err(|e| e.to_string())?
                        .ok_or_else(|| format!("unknown session {session_id}"))?;
                    let cwd = session.project_root.clone();
                    let session = Arc::new(session);
                    let (extended, providers) = crate::auto_title::load_configs_for(&cwd);
                    let redactor = crate::redact::RedactionTable::build(&extended.redact, &cwd)
                        .map_err(|e| e.to_string())?;
                    let generated = crate::auto_title::generate_session_title_once(
                        session,
                        extended,
                        providers,
                        Arc::new(redactor),
                        String::new(),
                        crate::session::TitleAction::Explicit,
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    match generated {
                        Some(title) => Ok(AsyncActionPayload::Text(title)),
                        None => Err("utility model returned no usable title".to_string()),
                    }
                },
            );
            return;
        }
        let req = crate::daemon::proto::Request::RenameSession {
            session_id,
            title: title.to_string(),
        };
        let title = title.to_string();
        self.push_plain("/rename: pending".to_string());
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("rename"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                agent_runner::daemon_request_blocking(req).map(|_| AsyncActionPayload::Text(title))
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
            Some(Ok(runner)) => (Some(runner.session_id), Some(runner.short_id.clone())),
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
    /// ([`crate::sysinfo::os_string`]); no build metadata. One `Plain` line
    /// per field, matching how other informational commands list output.
    pub(super) fn handle_version_command(&mut self) {
        self.push_plain(format!("cockpit {}", env!("CARGO_PKG_VERSION")));
        self.push_plain(format!("OS: {}", crate::sysinfo::os_string()));
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
            Some(Ok(runner)) => Some(runner.session_id),
            _ => self.launch.session_id,
        };
        let Some(session_id) = session_id else {
            self.push_plain("/note: no active session yet — send a message first".to_string());
            return;
        };
        let req = crate::daemon::proto::Request::RecordSessionNote {
            session_id,
            text: text.to_string(),
        };
        let text = text.to_string();
        self.push_plain("/note: pending".to_string());
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("note"),
            AsyncActionPolicy::AllowConcurrent,
            move || match agent_runner::daemon_request_blocking(req) {
                Ok(crate::daemon::proto::Response::NoteRecorded { .. }) => {
                    Ok(AsyncActionPayload::NoteRecorded { text })
                }
                Ok(_) => Err("unexpected daemon response".to_string()),
                Err(e) => Err(e),
            },
        );
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
    Set(crate::tools::sandbox_mode::SandboxMode),
    Network(bool),
}

pub(super) fn parse_sandbox_arg(args: &str) -> Result<SandboxCommand, String> {
    let normalized = args.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalized = normalized.to_ascii_lowercase();
    match normalized.as_str() {
        "" => Ok(SandboxCommand::Cycle),
        "on" => Ok(SandboxCommand::Set(
            crate::tools::sandbox_mode::SandboxMode::Sandbox,
        )),
        "off" => Ok(SandboxCommand::Set(
            crate::tools::sandbox_mode::SandboxMode::Off,
        )),
        "container" => Ok(SandboxCommand::Set(
            crate::tools::sandbox_mode::SandboxMode::Container,
        )),
        "container-readonly" | "container-ro" | "readonly" => Ok(SandboxCommand::Set(
            crate::tools::sandbox_mode::SandboxMode::ContainerReadonly,
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

pub(super) fn sandbox_mode_label(mode: crate::tools::sandbox_mode::SandboxMode) -> &'static str {
    match mode {
        crate::tools::sandbox_mode::SandboxMode::Off => "off",
        crate::tools::sandbox_mode::SandboxMode::Sandbox => "on",
        crate::tools::sandbox_mode::SandboxMode::Container => "container",
        crate::tools::sandbox_mode::SandboxMode::ContainerReadonly => "container-readonly",
    }
}

pub(super) fn next_sandbox_mode(
    current: crate::tools::sandbox_mode::SandboxMode,
    availability: &crate::container::ContainerAvailability,
) -> crate::tools::sandbox_mode::SandboxMode {
    let modes: &[crate::tools::sandbox_mode::SandboxMode] = if availability.available {
        &[
            crate::tools::sandbox_mode::SandboxMode::Off,
            crate::tools::sandbox_mode::SandboxMode::Sandbox,
            crate::tools::sandbox_mode::SandboxMode::Container,
            crate::tools::sandbox_mode::SandboxMode::ContainerReadonly,
        ]
    } else {
        &[
            crate::tools::sandbox_mode::SandboxMode::Off,
            crate::tools::sandbox_mode::SandboxMode::Sandbox,
        ]
    };
    let idx = modes.iter().position(|mode| *mode == current).unwrap_or(0);
    modes[(idx + 1) % modes.len()]
}

fn container_unavailable_label(
    availability: &crate::container::ContainerAvailability,
) -> &'static str {
    match availability.reason {
        Some(crate::container::ContainerUnavailableReason::HarnessInContainer) => {
            "Cockpit is running inside a container"
        }
        _ => "No docker/podman runtime found",
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

/// The text of the last assistant response in `history`, excluding
/// tool-call chrome (tool calls are non-`Agent` history variants).
/// `None` when no assistant message with text exists yet.
pub(super) fn last_agent_text(history: &[HistoryEntry]) -> Option<String> {
    history.iter().rev().find_map(|e| match e {
        HistoryEntry::Agent { text, .. } if !text.trim().is_empty() => Some(text.clone()),
        _ => None,
    })
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
/// [`crate::agents::chat_ownable_primaries`]) and the `active` agent name.
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

/// Discover the skills reachable from `cwd` and project them into bare-sugar
/// slash-menu entries (implementation note): one
/// `SkillCommand` per skill whose name does NOT collide with a builtin. A
/// colliding skill is dropped from the bare entries (logged once) but stays
/// invokable via the `/skill <name>` dispatcher. Discovery is frontmatter-only
/// (cheap) and tolerant — a discovery failure yields no skill entries.
pub(super) fn discover_bare_skill_commands(
    cwd: &Path,
    extended: &crate::config::extended::ExtendedConfig,
    agent_name: &str,
) -> Vec<SkillCommand> {
    let skills =
        crate::skills::discover_for_agent(cwd, &extended.skills, agent_name).unwrap_or_default();
    bare_skill_commands_from(skills)
}

/// Project discovered skills into bare-sugar slash-menu entries, dropping any
/// whose name collides with a builtin (the builtin keeps the bare name; the
/// skill stays reachable via `/skill <name>`). Split from
/// [`discover_bare_skill_commands`] so the collision filter is unit-testable
/// without touching the host's layered-config discovery.
pub(super) fn bare_skill_commands_from(skills: Vec<crate::skills::Skill>) -> Vec<SkillCommand> {
    let mut out = Vec::with_capacity(skills.len());
    for s in skills {
        // Model-only skills (`user-invocable: false`) are hidden from the
        // user's `/` menu but still eligible for auto-injection (their
        // description stays in the auto-select catalog).
        if !s.frontmatter.user_invocable {
            continue;
        }
        let name = s.frontmatter.name;
        if builtin_slash_name_taken(&name) {
            // Builtin shadows the bare name; surface the shadowed skill
            // non-intrusively (still reachable via `/skill <name>`).
            tracing::info!(
                skill = %name,
                "skill name collides with a builtin slash command; bare /{name} runs the builtin — invoke the skill via `/skill {name}`",
            );
            continue;
        }
        out.push(SkillCommand {
            name,
            description: s.frontmatter.description,
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
    use std::collections::BTreeSet;

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
}
