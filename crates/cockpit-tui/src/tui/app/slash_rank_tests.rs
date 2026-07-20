use super::{
    AgentCommandOutcome, App, SLASH_COMMANDS, SLASH_MENU_COUNTER_TEST_LOCK,
    SWARM_TOKEN_BURN_WARNING, agent_command_outcome, mcp_load_call_count, primary_swap_warning,
    program_on_path_call_count, reset_mcp_load_call_count, reset_program_on_path_call_count,
    slash_matches,
};
use std::collections::HashMap;

/// `/notes` → `/scratchpad` rename (implementation note):
/// the visible menu offers `/scratchpad` and the new `/note`, and the old
/// `/notes` is absent from the registry (it survives only as a hidden,
/// exact-match alias resolved in `complete_or_submit`).
#[test]
fn scratchpad_replaces_notes_and_note_is_registered() {
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "scratchpad"),
        "the renamed scratchpad command is visible"
    );
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "note"),
        "the new session-note command is visible"
    );
    assert!(
        !SLASH_COMMANDS.iter().any(|c| c.name == "notes"),
        "the old /notes command is gone from the visible menu"
    );
    // The hidden alias resolves to the registered scratchpad command.
    assert_eq!(
        super::hidden_slash_alias("notes").unwrap().name,
        "scratchpad"
    );
    // `/note <text>` is arg-taking (drives the trailing-space completion).
    let note = SLASH_COMMANDS.iter().find(|c| c.name == "note").unwrap();
    assert!(note.takes_args);
}

#[test]
fn slash_matches_hyphen_insensitive_model_settings() {
    let names: Vec<&str> = slash_matches("modelsettings", &HashMap::new())
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, vec!["model-settings"]);

    let names: Vec<&str> = slash_matches("model-set", &HashMap::new())
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, vec!["model-settings"]);
}

#[test]
fn slash_matches_hidden_aliases_as_canonical_commands() {
    let cases = [
        ("keybindings", "keys"),
        ("notes", "scratchpad"),
        ("toggle-redact", "toggle-redaction"),
    ];

    for (query, expected) in cases {
        let names: Vec<&str> = slash_matches(query, &HashMap::new())
            .into_iter()
            .map(|c| c.name)
            .collect();
        assert_eq!(names, vec![expected], "query {query}");
        assert!(
            !SLASH_COMMANDS.iter().any(|c| c.name == query),
            "{query} stays hidden"
        );
    }
}

#[test]
fn slash_matches_note_does_not_inject_scratchpad_alias() {
    let names: Vec<&str> = slash_matches("note", &HashMap::new())
        .into_iter()
        .map(|c| c.name)
        .collect();
    assert_eq!(names, vec!["note"]);
}

#[test]
fn hidden_alias_exact_lookup_uses_canonical_commands() {
    assert_eq!(
        super::hidden_slash_alias("modelsettings").unwrap().name,
        "model-settings"
    );
    assert_eq!(
        super::hidden_slash_alias("toggle-redact").unwrap().name,
        "toggle-redaction"
    );
    assert_eq!(
        super::hidden_slash_alias("keybindings").unwrap().name,
        "keys"
    );
    assert!(super::hidden_slash_alias("modelsetting").is_none());
}

#[test]
fn toggle_redaction_static_description_lists_ssh_source() {
    let command = SLASH_COMMANDS
        .iter()
        .find(|command| command.name == "toggle-redaction")
        .unwrap();
    assert!(command.description.contains("env/file/ssh"));
}

#[test]
fn fetch_models_static_description_names_provider_catalogs() {
    let command = SLASH_COMMANDS
        .iter()
        .find(|command| command.name == "fetch-models")
        .unwrap();
    assert!(command.description.contains("provider model catalogs"));
    assert!(command.description.contains("configured providers"));
}

#[test]
fn frequency_outranks_declaration_order() {
    // The last-declared command, given a count, jumps to the front.
    let last = SLASH_COMMANDS.last().unwrap().name;
    let mut counts = HashMap::new();
    counts.insert(last.to_string(), 9u64);
    let ranked = slash_matches("", &counts);
    assert_eq!(ranked.first().unwrap().name, last);
}

#[test]
fn equal_counts_fall_back_to_declaration_order() {
    let ranked = slash_matches("", &HashMap::new());
    let names: Vec<&str> = ranked.iter().map(|c| c.name).collect();
    let tmp = tempfile::tempdir().unwrap();
    let app = App::new(Some(tmp.path()), false);
    // `slash_matches` hides unavailable commands (`/editor` without
    // `$EDITOR`, `/lazygit` off `PATH`), so compare against the
    // available subset — otherwise this is env-dependent on CI.
    let _lock = SLASH_MENU_COUNTER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let declared: Vec<&str> = SLASH_COMMANDS
        .iter()
        .filter(|c| c.is_available(&app))
        .map(|c| c.name)
        .collect();
    assert_eq!(names, declared);
}

#[test]
fn slash_menu_cache_reuses_availability_across_queries() {
    let _lock = SLASH_MENU_COUNTER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    reset_program_on_path_call_count();
    reset_mcp_load_call_count();
    app.composer.set("/".to_string());
    app.reset_slash_window();
    assert_eq!(program_on_path_call_count(), 1);
    assert_eq!(mcp_load_call_count(), 1);

    app.composer.set("/m".to_string());
    app.reset_slash_window();
    let _ = app.slash_suggestions();
    app.composer.set("/mo".to_string());
    app.reset_slash_window();
    let _ = app.slash_suggestions();

    assert_eq!(
        program_on_path_call_count(),
        1,
        "PATH probing should happen once per menu-open interaction"
    );
    assert_eq!(
        mcp_load_call_count(),
        1,
        "MCP discovery should happen once per menu-open interaction"
    );
}

#[test]
fn slash_menu_cached_mcp_description_is_reused_per_render() {
    let _lock = SLASH_MENU_COUNTER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.composer.set("/mcp".to_string());

    reset_mcp_load_call_count();
    app.reset_slash_window();
    assert_eq!(mcp_load_call_count(), 1);

    for _ in 0..3 {
        let descriptions: Vec<String> = app
            .slash_suggestions()
            .iter()
            .map(|entry| entry.description(&app))
            .collect();
        assert!(
            descriptions
                .iter()
                .any(|d| d.contains("Manage MCP servers")),
            "mcp description should be present: {descriptions:?}"
        );
    }

    assert_eq!(
        mcp_load_call_count(),
        1,
        "render-time description reads must use the cached MCP description"
    );
}

#[test]
fn slash_menu_cache_rebuilds_after_close_and_reopen() {
    let _lock = SLASH_MENU_COUNTER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    reset_program_on_path_call_count();
    reset_mcp_load_call_count();
    app.composer.set("/".to_string());
    app.reset_slash_window();
    assert_eq!(program_on_path_call_count(), 1);
    assert_eq!(mcp_load_call_count(), 1);

    app.composer.clear();
    app.reset_slash_window();
    app.composer.set("/".to_string());
    app.reset_slash_window();

    assert_eq!(program_on_path_call_count(), 2);
    assert_eq!(mcp_load_call_count(), 2);
}

#[test]
fn takes_args_is_a_declared_field() {
    // `takes_args` is declared on the registry row so completion does
    // not infer behavior from description prose.
    let copy = SLASH_COMMANDS.iter().find(|c| c.name == "copy").unwrap();
    assert!(copy.takes_args, "/copy declares argument support");
    let settings = SLASH_COMMANDS
        .iter()
        .find(|c| c.name == "settings")
        .unwrap();
    assert!(!settings.takes_args, "/settings takes no argument");
}

#[test]
fn completion_text_adds_a_trailing_space_only_for_arg_commands() {
    // The Tab-completion target: arg-taking commands get a trailing
    // space so the cursor lands ready for the argument; bare commands
    // get none (`slash-command-tab-completion.md`).
    let copy = SLASH_COMMANDS.iter().find(|c| c.name == "copy").unwrap();
    assert_eq!(copy.completion_text(), "/copy ");
    let settings = SLASH_COMMANDS
        .iter()
        .find(|c| c.name == "settings")
        .unwrap();
    assert_eq!(settings.completion_text(), "/settings");
}

#[test]
fn sandbox_command_is_registered() {
    // `/sandbox` (sandboxing part 2) must be dispatchable.
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "sandbox"),
        "/sandbox must be a registered slash command"
    );
}

#[test]
fn quick_command_is_registered() {
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "quick"),
        "/quick must be a registered slash command"
    );
}

#[test]
fn plan_and_build_commands_are_registered() {
    // `/plan` and `/build` swap the primary agent (`plan.md §4.6.d`).
    for name in ["plan", "build"] {
        assert!(
            SLASH_COMMANDS.iter().any(|c| c.name == name),
            "/{name} must be a registered slash command"
        );
    }
}

#[test]
fn swarm_command_is_registered_with_token_warning() {
    // `/swarm` swaps the primary to `Swarm` via the same
    // `swap_primary_agent` path `/plan`/`/build` use (GOALS §24); its
    // registry description carries the token-burn caution.
    let swarm = SLASH_COMMANDS
        .iter()
        .find(|c| c.name == "swarm")
        .expect("/swarm must be a registered slash command");
    assert!(
        swarm.description.to_lowercase().contains("token"),
        "the /swarm entry must caution about token burn: {}",
        swarm.description
    );
}

#[test]
fn primary_swap_warning_fires_only_for_swarm() {
    // The token-burn caution rides the shared `swap_primary_agent` path
    // (implementation note), so every route onto
    // `Swarm` — `/swarm`, `/agent Swarm`, the `Shift+Tab` cycle —
    // surfaces the *same* text exactly once, and no other primary spams a
    // warning.
    assert_eq!(
        primary_swap_warning("Swarm"),
        Some(SWARM_TOKEN_BURN_WARNING),
        "landing on Swarm must fire the token-burn warning"
    );
    for quiet in ["Auto", "Plan", "Build", "builder", "explore"] {
        assert_eq!(
            primary_swap_warning(quiet),
            None,
            "{quiet} must not surface a swap warning"
        );
    }
}

#[test]
fn agent_command_outcome_switches_to_swarm() {
    // `Swarm` is a bundled chat-ownable primary, so `/agent Swarm`
    // (and the `Shift+Tab` cycle) route to a swap (GOALS §24). Build the
    // experimental-on order explicitly (the gate itself is covered in
    // `agents::tests`) so this routing test is config-independent.
    let order: Vec<String> = ["Auto", "Plan", "Build", "Swarm", "Build"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert!(order.iter().any(|n| n == "Swarm"), "{order:?}");
    assert_eq!(
        agent_command_outcome("Swarm", "Auto", &order),
        AgentCommandOutcome::Switch("Swarm".into())
    );
}

#[test]
fn agent_command_is_registered_and_takes_args() {
    // `/agent [name]` switches the active primary; bare lists them
    // (implementation note).
    let agent = SLASH_COMMANDS.iter().find(|c| c.name == "agent");
    assert!(agent.is_some(), "/agent must be a registered slash command");
    assert!(
        agent.unwrap().takes_args,
        "/agent documents `(arg: …)` so completion leaves a trailing space"
    );
}

#[test]
fn agent_command_outcome_switches_on_valid_name() {
    let order: Vec<String> = vec!["Auto".into(), "Plan".into(), "Build".into()];
    // A valid chat-ownable name routes to a switch (which the caller
    // sends through `swap_primary_agent`).
    assert_eq!(
        agent_command_outcome("Auto", "Plan", &order),
        AgentCommandOutcome::Switch("Auto".into())
    );
    // Surrounding whitespace is trimmed before matching.
    assert_eq!(
        agent_command_outcome("  Build  ", "Auto", &order),
        AgentCommandOutcome::Switch("Build".into())
    );
}

#[test]
fn agent_command_outcome_errors_on_bogus_name_without_switching() {
    let order: Vec<String> = vec!["Auto".into(), "Plan".into(), "Build".into()];
    let out = agent_command_outcome("bogus", "Auto", &order);
    match out {
        AgentCommandOutcome::Message(line) => {
            assert!(
                line.contains("`bogus`"),
                "names the bad value in backticks: {line}"
            );
            assert!(
                line.contains("Auto, Plan, Build"),
                "lists valid choices: {line}"
            );
        }
        other => panic!("a bogus name must not switch: {other:?}"),
    }
}

#[test]
fn agent_command_outcome_rejects_subagent_names() {
    // A subagent is never in `order`, so `/agent builder` errors and does
    // not switch.
    let order: Vec<String> = vec!["Auto".into(), "Plan".into(), "Build".into()];
    let out = agent_command_outcome("builder", "Auto", &order);
    assert!(matches!(out, AgentCommandOutcome::Message(ref l) if l.contains("`builder`")));
}

#[test]
fn agent_command_outcome_lists_and_marks_active_on_no_arg() {
    let order: Vec<String> = vec!["Auto".into(), "Plan".into(), "Build".into()];
    let out = agent_command_outcome("", "Plan", &order);
    match out {
        AgentCommandOutcome::Message(line) => {
            assert_eq!(line, "Available primary agents: Auto, Plan (active), Build");
        }
        other => panic!("bare /agent lists, does not switch: {other:?}"),
    }
}

#[test]
fn plan_agent_color_is_f8d749() {
    // The `Plan` agent shows in #f8d749 in the chrome/history.
    assert_eq!(
        crate::tui::history::agent_color("Plan"),
        crate::tui::theme::PLAN_YELLOW
    );
}

#[test]
fn rename_command_is_registered() {
    // `/rename` (rename-current-session) must be dispatchable.
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "rename"),
        "/rename must be a registered slash command"
    );
}

#[test]
fn config_command_is_registered() {
    // `/config` is a pure alias for `/settings` — it must be a
    // registered slash command so it appears in the menu, routed to
    // the same dialog-open dispatch arm.
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "config"),
        "/config must be a registered slash command"
    );
}

#[test]
fn skills_command_is_registered() {
    // `/skills` (read-only skill listing) must be dispatchable.
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "skills"),
        "/skills must be a registered slash command"
    );
}

#[test]
fn skill_dispatcher_is_registered_and_takes_args() {
    // `/skill <name> [task]` (the universal dispatcher) must be a
    // registered, arg-taking slash command — distinct from `/skills`.
    let skill = SLASH_COMMANDS
        .iter()
        .find(|c| c.name == "skill")
        .expect("/skill must be a registered slash command");
    assert!(
        skill.takes_args,
        "/skill must accept an argument (the skill name)"
    );
}

fn fake_skill(name: &str, description: &str) -> cockpit_core::skills::Skill {
    cockpit_core::skills::Skill {
        frontmatter: cockpit_core::skills::SkillFrontmatter {
            name: name.to_string(),
            description: description.to_string(),
            ..Default::default()
        },
        source: std::path::PathBuf::from(format!("/x/{name}/SKILL.md")),
    }
}

/// Like [`fake_skill`] but marked `user-invocable: false` (model-only),
/// so it should be hidden from the user's bare-`/` slash menu.
fn fake_model_only_skill(name: &str, description: &str) -> cockpit_core::skills::Skill {
    cockpit_core::skills::Skill {
        frontmatter: cockpit_core::skills::SkillFrontmatter {
            name: name.to_string(),
            description: description.to_string(),
            user_invocable: false,
            ..Default::default()
        },
        source: std::path::PathBuf::from(format!("/x/{name}/SKILL.md")),
    }
}

#[test]
fn bare_skill_entries_keep_noncolliding_with_descriptions() {
    // A skill whose name doesn't collide with a builtin surfaces as a
    // bare-`/<name>` entry carrying its own description.
    let entries = super::bare_skill_commands_from(vec![fake_skill(
        "commit-helper",
        "write a commit message",
    )]);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "commit-helper");
    assert_eq!(entries[0].description, "write a commit message");
}

#[test]
fn bare_skill_entries_hide_non_user_invocable() {
    // A `user-invocable: false` (model-only) skill is hidden from the
    // user's bare-`/` slash menu; a normal sibling still surfaces.
    let entries = super::bare_skill_commands_from(vec![
        fake_model_only_skill("model-only", "auto-injected only"),
        fake_skill("deploy", "deploy steps"),
    ]);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["deploy"],
        "model-only skill must not appear in the slash menu"
    );
}

#[test]
fn bare_skill_inventory_hides_conditionally_incompatible_skill() {
    let tmp = tempfile::tempdir().unwrap();
    let scan = tmp.path().join("skills");
    for (name, conditional) in [
        ("plain", ""),
        (
            "needs-web",
            "metadata:\n  hermes:\n    requires_toolsets: [web]\n",
        ),
    ] {
        let package = scan.join(name);
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: {name}\n{conditional}---\nBody"),
        )
        .unwrap();
    }
    let mut extended = cockpit_config::extended::ExtendedConfig::default();
    extended.skills.scan_dirs = vec![scan.to_string_lossy().into_owned()];

    let entries =
        super::discover_bare_skill_commands(tmp.path(), &extended, "agent-that-does-not-exist");
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, ["plain"]);
}

#[test]
fn bare_skill_entries_drop_builtin_collisions() {
    // A skill named like a builtin (`agent`) — and one named `skill`
    // (the dispatcher is itself a builtin) — must NOT claim the bare
    // name; both are dropped from the bare entries (still reachable via
    // `/skill <name>`). The non-colliding one survives.
    let entries = super::bare_skill_commands_from(vec![
        fake_skill("agent", "shadowed by /agent"),
        fake_skill("skill", "shadowed by /skill"),
        fake_skill("deploy", "deploy steps"),
    ]);
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["deploy"],
        "only the non-colliding skill survives"
    );
    // The builtins themselves still own their bare names.
    assert!(super::builtin_slash_name_taken("agent"));
    assert!(super::builtin_slash_name_taken("skill"));
    assert!(!super::builtin_slash_name_taken("deploy"));
}

#[test]
fn skill_dispatcher_invokes_known_name_bare_and_with_args() {
    use super::{SkillDispatch, resolve_skill_dispatch};
    let names = ["commit-helper", "deploy"];
    // Bare: known name, no task.
    assert_eq!(
        resolve_skill_dispatch("commit-helper", &names),
        SkillDispatch::Invoke {
            name: "commit-helper".into(),
            task: String::new()
        }
    );
    // With trailing args: forwarded verbatim as the task input.
    assert_eq!(
        resolve_skill_dispatch("commit-helper fix the auth bug", &names),
        SkillDispatch::Invoke {
            name: "commit-helper".into(),
            task: "fix the auth bug".into()
        }
    );
}

#[test]
fn skill_dispatcher_reaches_builtin_colliding_skill() {
    use super::{SkillDispatch, resolve_skill_dispatch};
    // A skill named like a builtin (`agent`) is omitted from bare sugar
    // but the dispatcher still resolves it (it's in the discovered set).
    let names = ["agent"];
    assert_eq!(
        resolve_skill_dispatch("agent do the thing", &names),
        SkillDispatch::Invoke {
            name: "agent".into(),
            task: "do the thing".into()
        }
    );
}

#[test]
fn skill_dispatcher_bare_lists_skills_no_silent_noop() {
    use super::{SkillDispatch, resolve_skill_dispatch};
    let names = ["commit-helper", "deploy"];
    match resolve_skill_dispatch("", &names) {
        SkillDispatch::Error(msg) => {
            assert!(msg.contains("commit-helper") && msg.contains("deploy"));
        }
        other => panic!("bare /skill must error with the list, got {other:?}"),
    }
    // Even with no skills discovered it must not silently no-op.
    assert!(matches!(
        resolve_skill_dispatch("", &[]),
        SkillDispatch::Error(_)
    ));
}

#[test]
fn skill_dispatcher_unknown_name_is_clear_error() {
    use super::{SkillDispatch, resolve_skill_dispatch};
    let names = ["deploy"];
    match resolve_skill_dispatch("nope", &names) {
        SkillDispatch::Error(msg) => {
            assert!(msg.contains("unknown skill `nope`"));
            assert!(msg.contains("deploy"), "lists the available skills");
        }
        other => panic!("unknown skill must be a clear error, got {other:?}"),
    }
}

#[test]
fn side_command_is_registered() {
    // `/side` (ephemeral throwaway side conversation) must be dispatchable.
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "side"),
        "/side must be a registered slash command"
    );
}

#[test]
fn permissions_command_is_registered() {
    // `/permissions` (delete-only approvals manager) must be dispatchable.
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "permissions"),
        "/permissions must be a registered slash command"
    );
}

#[test]
fn copy_pick_command_is_registered() {
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "copy-pick"),
        "/copy-pick must be a registered slash command"
    );
}

#[test]
fn session_command_is_not_registered() {
    // The dead `/session` subcommand stub was removed in favor of
    // `/rename`; it must no longer appear in the menu or dispatch.
    assert!(
        !SLASH_COMMANDS.iter().any(|c| c.name == "session"),
        "/session must not be a registered slash command"
    );
}

#[test]
fn copy_command_is_registered() {
    // `/copy` (copy-last-response) must be dispatchable.
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "copy"),
        "/copy must be a registered slash command"
    );
}

#[test]
fn export_command_is_registered_and_visible() {
    // `/export` must be a registered, available (menu-visible) slash
    // command. The `debug` argument is hidden — it's an arg of
    // `/export`, never its own menu entry — so there is no `export
    // debug` command name.
    let export = SLASH_COMMANDS
        .iter()
        .find(|c| c.name == "export")
        .expect("/export must be a registered slash command");
    let tmp = tempfile::tempdir().unwrap();
    let app = App::new(Some(tmp.path()), false);
    assert!(
        export.is_available(&app),
        "/export must be visible in the menu"
    );
    assert!(
        !SLASH_COMMANDS.iter().any(|c| c.name == "export debug"),
        "`debug` is a hidden arg of /export, not its own command"
    );
}

#[test]
fn ps_and_stop_are_registered() {
    // `/ps` (current-session task list) and `/stop` (current-session
    // task stop) must both be dispatchable; `/schedule` (all-sessions) is
    // kept alongside them.
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "ps"),
        "/ps must be a registered slash command"
    );
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "stop"),
        "/stop must be a registered slash command"
    );
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "schedule"),
        "/schedule must remain a registered slash command"
    );
}

#[test]
fn version_command_is_registered_visible_and_bare() {
    // `/version` must be a registered, menu-visible command that takes
    // no argument (its description carries no `arg:` marker).
    let version = SLASH_COMMANDS
        .iter()
        .find(|c| c.name == "version")
        .expect("/version must be a registered slash command");
    let tmp = tempfile::tempdir().unwrap();
    let app = App::new(Some(tmp.path()), false);
    assert!(
        version.is_available(&app),
        "/version must be visible in the menu"
    );
    assert!(!version.takes_args, "/version takes no argument");
}

#[test]
fn new_and_clear_are_both_registered_aliases() {
    // `/new` and `/clear` are both menu entries routing to the one
    // fresh-session handler (`"new" | "clear"` dispatch arm).
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "new"),
        "/new must be a registered slash command"
    );
    assert!(
        SLASH_COMMANDS.iter().any(|c| c.name == "clear"),
        "/clear must be a registered slash command"
    );
}
