//! Tests for agent definition parsing, override resolution, invariant
//! validation, eject/reset, and name→path resolution.

use std::fs;
use std::path::Path;

use super::invariants::{LOCK_WRITE_TOOLS, SANDBOX_ONLY_TOOLS};
use super::*;

/// A `.cockpit/` config dir under `cwd`, so the discovery walk-up finds a
/// project-scoped layer. Returns the `agents/` subdir.
fn project_agents_dir(cwd: &Path) -> std::path::PathBuf {
    let dir = cwd.join(".cockpit").join("agents");
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_large_agent(path: &Path, size: u64) {
    fs::write(path, "---\ndescription: too large\n---\nbody\n").unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .set_len(size)
        .unwrap();
}

#[test]
fn configured_agent_dirs_resolve_relative_to_defining_config_file() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("project").join(".cockpit");
    fs::create_dir_all(&config_dir).unwrap();
    let config = config_dir.join("config.json");
    fs::write(&config, r#"{"agent_dirs":["relative-agents"]}"#).unwrap();

    let dirs = configured_agent_dirs_for_paths(&[config.clone()]);

    assert_eq!(dirs, vec![config_dir.join("relative-agents")]);
}

// ── Parsing ──────────────────────────────────────────────────────────────

#[test]
fn parse_agent_reads_frontmatter_and_body() {
    let text = "---\n\
description: A custom reviewer.\n\
mode: subagent\n\
model: anthropic/claude-opus-4-7\n\
temperature: 0.3\n\
tools: [read, bash, search]\n\
scanToolResults: true\n\
---\n\
\n\
You are a reviewer. Be terse.\n";
    let def = parse_agent(text, "my-reviewer", "x.md".into()).unwrap();
    assert_eq!(def.name, "my-reviewer");
    assert_eq!(def.description, "A custom reviewer.");
    assert_eq!(def.mode, AgentMode::Subagent);
    assert_eq!(def.model.as_deref(), Some("anthropic/claude-opus-4-7"));
    assert_eq!(def.temperature, Some(0.3));
    assert_eq!(
        def.tools,
        Some(vec!["read".into(), "bash".into(), "search".into()])
    );
    assert_eq!(def.scan_tool_results, Some(true));
    assert_eq!(def.prompt, "You are a reviewer. Be terse.");
}

#[test]
fn parse_agent_defaults_mode_to_all() {
    let text = "---\ndescription: x\n---\nbody\n";
    let def = parse_agent(text, "a", "a.md".into()).unwrap();
    assert_eq!(def.mode, AgentMode::All);
    assert!(def.tools.is_none());
}

#[test]
fn parse_agent_missing_description_fails_with_source() {
    let text = "---\nmode: subagent\n---\nbody\n";
    let err = parse_agent(text, "bad", "/p/bad.md".into()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("bad"), "{msg}");
    assert!(msg.contains("/p/bad.md"), "names the source path: {msg}");
}

#[test]
fn parse_agent_bad_yaml_fails_with_source() {
    let text = "---\ndescription: [unterminated\n---\nbody\n";
    let err = parse_agent(text, "bad", "/p/bad.md".into()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("/p/bad.md"), "names the source: {msg}");
    assert!(msg.contains("invalid frontmatter"), "{msg}");
}

#[test]
fn parse_agent_no_frontmatter_fails() {
    let text = "just a body, no fence\n";
    let err = parse_agent(text, "x", "x.md".into()).unwrap_err();
    assert!(format!("{err}").contains("no YAML frontmatter"));
}

#[test]
fn load_from_file_rejects_oversized_agent_markdown() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("large.md");
    write_large_agent(&path, MAX_MARKDOWN_BYTES + 1);

    let err = load_from_file(&path).unwrap_err();

    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[test]
fn load_from_dir_rejects_oversized_mode_markdown() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("agents");
    let agent_dir = dir.join("large");
    fs::create_dir_all(&agent_dir).unwrap();
    write_large_agent(
        &agent_dir.join(crate::config::extended::LlmMode::Normal.prompt_file()),
        MAX_MARKDOWN_BYTES + 1,
    );

    let err = load_from_dir(&dir, "large").unwrap_err();

    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[test]
fn list_all_excludes_oversized_custom_agent() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    fs::write(
        dir.join("small.md"),
        "---\ndescription: small\nmode: subagent\n---\nbody\n",
    )
    .unwrap();
    write_large_agent(&dir.join("large.md"), MAX_MARKDOWN_BYTES + 1);

    let names: Vec<String> = list_all(tmp.path()).into_iter().map(|a| a.name).collect();

    assert!(names.iter().any(|name| name == "small"), "{names:?}");
    assert!(!names.iter().any(|name| name == "large"), "{names:?}");
}

// ── Round-trip / eject faithfulness ──────────────────────────────────────

#[test]
fn to_markdown_round_trips_through_parse() {
    let def = embedded_default("builder").unwrap();
    let md = def.to_markdown().unwrap();
    // Re-parse the ejected form.
    let parsed = parse_agent(&md, "builder", "builder.md".into()).unwrap();
    assert_eq!(parsed.description, def.description);
    assert_eq!(parsed.mode, def.mode);
    assert_eq!(parsed.tools, def.tools);
    assert_eq!(parsed.scan_tool_results, def.scan_tool_results);
    assert_eq!(parsed.prompt, def.prompt);
}

// ── Invariant validation ─────────────────────────────────────────────────

fn def_with_tools(name: &str, tools: &[&str]) -> AgentDef {
    AgentDef {
        name: name.into(),
        description: "d".into(),
        mode: AgentMode::Subagent,
        model: None,
        temperature: None,
        tools: Some(tools.iter().map(|s| s.to_string()).collect()),
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: None,
        permission: None,
        prompt: "body".into(),
        prompt_variants: std::collections::HashMap::new(),
        source: "x.md".into(),
    }
}

#[test]
fn write_tools_are_role_driven_not_name_bound() {
    // Write/lock tools are no longer restricted to a single hard-coded writer
    // name (`builder`): any agent that names them is a write-capable agent
    // (prompt `lock-manager-multi-writer.md`). The single-writer guarantee is
    // upheld by the lock manager keyed by `(session, agent)`, not by a name
    // check at load. So a non-`builder` agent granting a write tool now
    // validates — its concurrent writes are arbitrated path-granular.
    let def = def_with_tools("custom-writer", &["read", "writeunlock"]);
    assert!(
        validate_invariants(&def).is_ok(),
        "any write-capable agent may hold write/lock tools"
    );
    // The full write/lock set is admissible too.
    let full = def_with_tools("custom-writer", LOCK_WRITE_TOOLS);
    assert!(validate_invariants(&full).is_ok());
}

#[test]
fn spawn_tool_is_swarm_and_bee_only() {
    // A non-`Swarm`/`bee` agent naming the recursive fan-out tool is rejected
    // — it is the sole leaf-termination exception, held only by `Swarm` and
    // its `bee` worker (GOALS §24/§26).
    let def = def_with_tools("Build", &["read", "spawn"]);
    let err = validate_invariants(&def).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("`spawn`"), "{msg}");
    assert!(msg.contains("leaf-termination"), "{msg}");
    // `Swarm` (primary) and `bee` (worker) may both hold it.
    let mut ok = def_with_tools("Swarm", &["read", "spawn"]);
    ok.mode = AgentMode::Primary;
    assert!(validate_invariants(&ok).is_ok());
    let bee = def_with_tools("bee", &["read", "spawn"]);
    assert!(validate_invariants(&bee).is_ok());
}

#[test]
fn builder_with_write_tools_is_allowed() {
    let def = def_with_tools("builder", LOCK_WRITE_TOOLS);
    assert!(validate_invariants(&def).is_ok());
}

#[test]
fn user_agent_with_sandbox_tool_is_rejected() {
    for t in SANDBOX_ONLY_TOOLS {
        let def = def_with_tools("my-agent", &["read", t]);
        let err = validate_invariants(&def).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains(&format!("`{t}`")), "{msg}");
        assert!(msg.contains("docs-answerer-only"), "{msg}");
    }
}

#[test]
fn even_a_writer_cannot_get_sandbox_tools() {
    // The docs-answerer sandbox guard is independent of write-capability:
    // naming `grep` is rejected even for a write-capable agent like `builder`.
    let def = def_with_tools("builder", &["grep"]);
    let err = validate_invariants(&def).unwrap_err();
    assert!(format!("{err}").contains("docs-answerer-only"));
}

#[test]
fn subagent_with_harness_tool_is_rejected() {
    // The external-harness tools are primary-only (leaf-termination). A
    // subagent-mode custom agent naming one is rejected with an actionable
    // message.
    for t in crate::agents::invariants::PRIMARY_ONLY_TOOLS {
        let def = def_with_tools("my-sub", &["read", t]);
        assert_eq!(def.mode, AgentMode::Subagent);
        let err = validate_invariants(&def).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains(&format!("`{t}`")), "{msg}");
        assert!(msg.contains("primary"), "{msg}");
    }
}

#[test]
fn primary_with_harness_tool_is_allowed() {
    // A primary (or all-mode) custom agent may hold the harness tools.
    let mut def = def_with_tools("my-primary", &["read", "harness_invoke", "harness_list"]);
    def.mode = AgentMode::Primary;
    assert!(validate_invariants(&def).is_ok());
    def.mode = AgentMode::All;
    assert!(validate_invariants(&def).is_ok());
}

#[test]
fn unknown_tool_name_is_rejected_backticked() {
    let def = def_with_tools("my-agent", &["read", "frobnicate"]);
    let err = validate_invariants(&def).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("unknown tool `frobnicate`"), "{msg}");
}

#[test]
fn absent_tools_grant_validates() {
    let mut def = def_with_tools("my-agent", &[]);
    def.tools = None;
    assert!(validate_invariants(&def).is_ok());
}

// ── Override resolution ──────────────────────────────────────────────────

#[test]
fn resolve_returns_embedded_default_when_no_override() {
    let tmp = tempfile::tempdir().unwrap();
    let def = resolve(tmp.path(), "builder").unwrap().unwrap();
    // Embedded default has an empty source.
    assert!(def.source.as_os_str().is_empty());
    assert_eq!(def.name, "builder");
}

#[test]
fn resolve_prefers_on_disk_override() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    fs::write(
        dir.join("builder.md"),
        "---\ndescription: edited builder\nmode: subagent\ntools: [read]\n---\nNEW BODY\n",
    )
    .unwrap();
    let def = resolve(tmp.path(), "builder").unwrap().unwrap();
    assert!(!def.source.as_os_str().is_empty(), "override has a source");
    assert_eq!(def.description, "edited builder");
    assert_eq!(def.prompt, "NEW BODY");
    assert_eq!(def.tools, Some(vec!["read".to_string()]));
}

#[test]
fn ignore_config_filters_configured_agent_dirs_inside_trust_root() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_agent_dir = tmp.path().join("repo-agents");
    fs::create_dir_all(&repo_agent_dir).unwrap();
    let cfg_dir = tempfile::tempdir().unwrap();
    let cfg_path = cfg_dir.path().join("config.json");
    fs::write(
        &cfg_path,
        format!(
            "{{\"agent_dirs\":[{}]}}",
            serde_json::to_string(&repo_agent_dir).unwrap()
        ),
    )
    .unwrap();
    let policy = crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(tmp.path()).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
    };

    let dirs = crate::config::trust::with_workspace_trust_policy(policy, || {
        // SAFETY: test-scoped config override restored before returning.
        unsafe {
            std::env::set_var(crate::config::dirs::COCKPIT_CONFIG_ENV, &cfg_path);
        }
        let dirs = agent_search_dirs(tmp.path());
        unsafe {
            std::env::remove_var(crate::config::dirs::COCKPIT_CONFIG_ENV);
        }
        dirs
    });

    assert!(
        !dirs.iter().any(|dir| dir == &repo_agent_dir),
        "agent_dirs under ignore-config root must be excluded: {dirs:?}"
    );
}

#[test]
fn custom_name_colliding_with_builtin_is_treated_as_override() {
    // A file named `explore.md` overrides the built-in `explore` rather
    // than appearing as a separate custom agent.
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    fs::write(
        dir.join("explore.md"),
        "---\ndescription: my explore\n---\nbody\n",
    )
    .unwrap();
    let listings = list_all(tmp.path());
    let explore_rows: Vec<_> = listings.iter().filter(|l| l.name == "explore").collect();
    assert_eq!(explore_rows.len(), 1, "explore appears exactly once");
    assert!(
        matches!(
            explore_rows[0].kind,
            AgentKind::Builtin { overridden: true }
        ),
        "the collision is an override, not a second custom agent"
    );
}

#[test]
fn resolve_returns_none_for_unknown_name() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(resolve(tmp.path(), "no-such-agent").unwrap().is_none());
}

#[test]
fn resolve_malformed_override_fails_loudly() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    let path = dir.join("builder.md");
    fs::write(&path, "---\nmode: subagent\n---\nno description\n").unwrap();
    let err = resolve(tmp.path(), "builder").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("builder.md"), "names the source: {msg}");
    // Did NOT silently fall back to the embedded default.
}

#[test]
fn resolve_rejects_override_with_invariant_violation() {
    // An override that names a docs-answerer-only sandbox tool is rejected at
    // resolve time (it never silently falls back to the embedded default).
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    fs::write(
        dir.join("explore.md"),
        "---\ndescription: e\ntools: [read, glob]\n---\nbody\n",
    )
    .unwrap();
    let err = resolve(tmp.path(), "explore").unwrap_err();
    assert!(format!("{err}").contains("docs-answerer-only"));
}

// ── list_all ─────────────────────────────────────────────────────────────

#[test]
fn list_all_lists_builtins_and_custom() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    fs::write(
        dir.join("my-reviewer.md"),
        "---\ndescription: reviewer\nmode: subagent\n---\nbody\n",
    )
    .unwrap();
    let listings = list_all(tmp.path());
    for name in BUILTIN_AGENT_NAMES {
        assert!(
            listings.iter().any(|l| &l.name == name),
            "built-in {name} listed"
        );
    }
    let custom = listings.iter().find(|l| l.name == "my-reviewer").unwrap();
    assert_eq!(custom.kind, AgentKind::Custom);
    assert!(custom.def.is_ok());
}

// ── Eject ────────────────────────────────────────────────────────────────

#[test]
fn eject_writes_faithful_file() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join(".cockpit");
    fs::create_dir_all(&config_dir).unwrap();
    let (path, written) = eject_builtin(tmp.path(), &config_dir, "builder").unwrap();
    assert!(written, "first eject writes a new file");
    assert!(path.exists());
    let on_disk = fs::read_to_string(&path).unwrap();
    let parsed = parse_agent(&on_disk, "builder", path.clone()).unwrap();
    let embedded = embedded_default("builder").unwrap();
    assert_eq!(parsed.description, embedded.description);
    assert_eq!(parsed.tools, embedded.tools);
    assert_eq!(parsed.prompt, embedded.prompt);
    // And the ejected file is now the resolved override.
    let resolved = resolve(tmp.path(), "builder").unwrap().unwrap();
    assert!(!resolved.source.as_os_str().is_empty());
}

#[test]
fn eject_does_not_clobber_existing_override() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join(".cockpit");
    let dir = project_agents_dir(tmp.path());
    let existing = dir.join("builder.md");
    fs::write(
        &existing,
        "---\ndescription: mine\ntools: [read]\n---\nMY EDITS\n",
    )
    .unwrap();
    let (path, written) = eject_builtin(tmp.path(), &config_dir, "builder").unwrap();
    assert!(!written, "must not clobber");
    assert_eq!(path, existing);
    // The user's content is intact.
    assert!(fs::read_to_string(&existing).unwrap().contains("MY EDITS"));
}

#[test]
fn eject_rejects_non_builtin() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join(".cockpit");
    assert!(eject_builtin(tmp.path(), &config_dir, "my-custom").is_err());
}

// ── Reset ────────────────────────────────────────────────────────────────

#[test]
fn reset_all_removes_builtin_overrides_only() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    // Two built-in overrides + one custom agent.
    fs::write(
        dir.join("builder.md"),
        "---\ndescription: c\ntools: [read]\n---\nb\n",
    )
    .unwrap();
    fs::write(dir.join("explore.md"), "---\ndescription: e\n---\nb\n").unwrap();
    fs::write(dir.join("my-reviewer.md"), "---\ndescription: r\n---\nb\n").unwrap();

    let removed = reset_all_builtins(tmp.path()).unwrap();
    assert_eq!(removed.len(), 2, "only the two built-in overrides removed");
    assert!(!dir.join("builder.md").exists());
    assert!(!dir.join("explore.md").exists());
    assert!(
        dir.join("my-reviewer.md").exists(),
        "custom agent is untouched by reset"
    );
    // Built-ins now resolve from embedded again.
    assert!(
        resolve(tmp.path(), "builder")
            .unwrap()
            .unwrap()
            .source
            .as_os_str()
            .is_empty()
    );
}

#[test]
fn reset_with_no_overrides_is_a_noop() {
    let tmp = tempfile::tempdir().unwrap();
    project_agents_dir(tmp.path());
    let removed = reset_all_builtins(tmp.path()).unwrap();
    assert!(removed.is_empty());
}

// ── name→path resolution (flat-file form; dir-form readiness) ────────────

#[test]
fn agent_path_in_uses_flat_form_by_default() {
    let tmp = tempfile::tempdir().unwrap();
    let p = agent_path_in(tmp.path(), "builder");
    assert!(p.ends_with("builder.md"), "flat-file form: {p:?}");
}

#[test]
fn agent_path_in_prefers_existing_flat_file() {
    let tmp = tempfile::tempdir().unwrap();
    let flat = tmp.path().join("builder.md");
    fs::write(&flat, "x").unwrap();
    assert_eq!(agent_path_in(tmp.path(), "builder"), flat);
}

#[test]
fn agent_path_in_surfaces_dir_form_when_present() {
    // Forward-compat: a `<name>/` directory (the future per-mode layout)
    // is surfaced rather than assuming `<name>.md`.
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("builder");
    fs::create_dir_all(&dir).unwrap();
    let resolved = agent_path_in(tmp.path(), "builder");
    assert_eq!(resolved, dir, "dir form is surfaced: {resolved:?}");
    assert!(resolved.is_dir());
}

#[test]
fn agent_path_in_prefers_dir_form_over_flat() {
    // When both a flat `<name>.md` and a per-mode `<name>/` directory exist,
    // the richer directory form wins — it falls back to the flat sibling
    // internally for any absent mode.
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("rev.md"), "x").unwrap();
    let dir = tmp.path().join("rev");
    fs::create_dir_all(&dir).unwrap();
    assert_eq!(agent_path_in(tmp.path(), "rev"), dir);
}

// ── Per-`llm_mode` directory-form resolution ──────────────────────────────

use crate::config::extended::LlmMode;

/// Write a per-mode agent markdown file (frontmatter + body) into
/// `<agents>/<name>/<mode>.md`.
fn write_mode_file(agents: &Path, name: &str, mode: LlmMode, body: &str) {
    let dir = agents.join(name);
    fs::create_dir_all(&dir).unwrap();
    let text = format!("---\ndescription: A custom agent.\nmode: subagent\n---\n\n{body}\n");
    fs::write(dir.join(mode.prompt_file()), text).unwrap();
}

#[test]
fn dir_form_selects_per_mode_prompt() {
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    write_mode_file(&agents, "rev", LlmMode::Normal, "NORMAL BODY");
    write_mode_file(&agents, "rev", LlmMode::Frontier, "FRONTIER BODY");
    write_mode_file(&agents, "rev", LlmMode::Defensive, "DEFENSIVE BODY");

    let def = resolve(tmp.path(), "rev").unwrap().expect("agent resolves");
    assert_eq!(def.resolved_prompt_for(LlmMode::Normal), "NORMAL BODY");
    assert_eq!(def.resolved_prompt_for(LlmMode::Frontier), "FRONTIER BODY");
    assert_eq!(
        def.resolved_prompt_for(LlmMode::Defensive),
        "DEFENSIVE BODY"
    );
}

#[test]
fn dir_form_missing_mode_falls_back_to_flat_sibling() {
    // The directory has only `defensive.md`; the flat `<name>.md` sibling is
    // the fallback for the absent `normal` mode.
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    write_mode_file(&agents, "rev", LlmMode::Defensive, "DEFENSIVE BODY");
    fs::write(
        agents.join("rev.md"),
        "---\ndescription: Flat fallback.\nmode: subagent\n---\n\nFLAT BODY\n",
    )
    .unwrap();

    let def = resolve(tmp.path(), "rev").unwrap().expect("agent resolves");
    assert_eq!(
        def.resolved_prompt_for(LlmMode::Defensive),
        "DEFENSIVE BODY"
    );
    // `normal.md` is absent → fall back to the flat sibling body.
    assert_eq!(def.resolved_prompt_for(LlmMode::Normal), "FLAT BODY");
    // `frontier.md` is also absent and no normal body exists → flat fallback.
    assert_eq!(def.resolved_prompt_for(LlmMode::Frontier), "FLAT BODY");
}

#[test]
fn dir_form_frontier_falls_back_to_normal_before_flat() {
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    write_mode_file(&agents, "rev", LlmMode::Defensive, "DEFENSIVE BODY");
    write_mode_file(&agents, "rev", LlmMode::Normal, "NORMAL BODY");
    fs::write(
        agents.join("rev.md"),
        "---\ndescription: Flat fallback.\nmode: subagent\n---\n\nFLAT BODY\n",
    )
    .unwrap();

    let def = resolve(tmp.path(), "rev").unwrap().expect("agent resolves");
    assert_eq!(def.resolved_prompt_for(LlmMode::Frontier), "NORMAL BODY");
}

#[test]
fn dir_form_missing_mode_no_flat_errors_naming_agent_and_mode() {
    // Only `defensive.md` and no flat sibling: resolving still works (the
    // present mode body is the flat fallback), and the absent mode falls
    // back to that present body rather than erroring — a partial directory
    // still loads. The hard error is the empty-directory case below.
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    write_mode_file(&agents, "rev", LlmMode::Defensive, "DEFENSIVE BODY");
    let def = resolve(tmp.path(), "rev").unwrap().expect("agent resolves");
    assert_eq!(
        def.resolved_prompt_for(LlmMode::Defensive),
        "DEFENSIVE BODY"
    );
    assert_eq!(def.resolved_prompt_for(LlmMode::Normal), "DEFENSIVE BODY");
    assert_eq!(def.resolved_prompt_for(LlmMode::Frontier), "DEFENSIVE BODY");
}

#[test]
fn dir_form_empty_directory_errors_naming_agent() {
    // A `<name>/` directory with no mode files and no flat sibling is
    // malformed: error naming the agent.
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    fs::create_dir_all(agents.join("rev")).unwrap();
    let err = resolve(tmp.path(), "rev").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("rev"), "names the agent: {msg}");
    assert!(
        msg.contains("defensive.md") && msg.contains("normal.md") && msg.contains("frontier.md"),
        "names the missing mode files: {msg}"
    );
}

#[test]
fn flat_file_agent_is_single_mode_in_both_modes() {
    // A flat-file agent has no per-mode variants — the same body serves
    // every mode.
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    fs::write(
        agents.join("rev.md"),
        "---\ndescription: Single mode.\nmode: subagent\n---\n\nONE BODY\n",
    )
    .unwrap();
    let def = resolve(tmp.path(), "rev").unwrap().expect("agent resolves");
    assert_eq!(def.resolved_prompt_for(LlmMode::Normal), "ONE BODY");
    assert_eq!(def.resolved_prompt_for(LlmMode::Frontier), "ONE BODY");
    assert_eq!(def.resolved_prompt_for(LlmMode::Defensive), "ONE BODY");
    assert!(def.prompt_variants.is_empty());
}

#[test]
fn embedded_builtin_falls_back_to_flat_when_a_variant_is_absent() {
    // Belt-and-suspenders: a built-in whose `prompt_variants` lacks the
    // requested mode still returns a valid body via the flat fallback. Mutate
    // a real embedded def to simulate a missing variant.
    let mut def = embedded_default("Build").unwrap();
    let flat = def.prompt.clone();
    def.prompt_variants.remove(&LlmMode::Normal);
    assert_eq!(
        def.resolved_prompt_for(LlmMode::Normal),
        flat,
        "absent normal variant must fall back to the flat body"
    );
    assert_eq!(
        def.resolved_prompt_for(LlmMode::Frontier),
        flat,
        "absent frontier and normal variants must fall back to the flat body"
    );
    // Drop all variants → every mode resolves to the flat body.
    def.prompt_variants.clear();
    assert_eq!(def.resolved_prompt_for(LlmMode::Defensive), flat);
    assert_eq!(def.resolved_prompt_for(LlmMode::Normal), flat);
    assert_eq!(def.resolved_prompt_for(LlmMode::Frontier), flat);
}

#[test]
fn dir_form_enforces_invariants_at_load() {
    // Invariant validation runs for the per-mode (directory) form too: a
    // per-mode agent that names a docs-answerer-only sandbox tool is rejected
    // at load, regardless of mode. (Write/lock tools are no longer rejected by
    // name — that guarantee now lives in the lock manager.)
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    let dir = agents.join("rev");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("defensive.md"),
        "---\ndescription: x\nmode: subagent\ntools: [read, grep]\n---\n\nB\n",
    )
    .unwrap();
    let err = resolve(tmp.path(), "rev").unwrap_err();
    assert!(
        format!("{err}").contains("docs-answerer-only"),
        "core invariant must be enforced in the dir form: {err}"
    );
}

// ── chat-ownable primaries + cycle ─────────────────────────────────────────

#[test]
fn is_chat_ownable_classifies_modes() {
    assert!(AgentMode::All.is_chat_ownable());
    assert!(AgentMode::Primary.is_chat_ownable());
    assert!(!AgentMode::Subagent.is_chat_ownable());
}

#[test]
fn multireview_is_hidden_from_chat_ownable_cycle() {
    let tmp = tempfile::tempdir().unwrap();
    project_agents_dir(tmp.path());
    let order = chat_ownable_primaries_with(tmp.path(), true);
    assert!(
        !order.iter().any(|n| n == "Multireview"),
        "hidden primary must not be listed or cycled: {order:?}"
    );
    assert!(is_hidden_primary("Multireview"));
}

#[test]
fn scout_and_multireview_builtin_surfaces_are_read_only() {
    for name in ["scout", "Multireview"] {
        let def = embedded_default(name).expect("embedded default");
        let tools = def.tools.as_ref().expect("explicit builtin tools");
        assert!(tools.iter().any(|t| t == "spawn"), "{name} holds spawn");
        for write_tool in LOCK_WRITE_TOOLS {
            assert!(
                !tools.iter().any(|t| t == write_tool),
                "{name} must not hold {write_tool}"
            );
        }
        assert!(
            !tools.iter().any(|t| matches!(t.as_str(), "write" | "edit")),
            "{name} must not hold raw write/edit"
        );
        validate_invariants(&def).expect("read-only builtin invariant");
    }
}

#[test]
fn next_primary_in_cycle_wraps_builtins_only() {
    let order: Vec<String> = vec!["Auto".into(), "Plan".into(), "Build".into()];
    assert_eq!(next_primary_in_cycle("Auto", &order), "Plan");
    assert_eq!(next_primary_in_cycle("Plan", &order), "Build");
    // Build wraps back to Auto when there are no user-defined primaries.
    assert_eq!(next_primary_in_cycle("Build", &order), "Auto");
}

#[test]
fn next_primary_in_cycle_wraps_through_user_primaries() {
    let order: Vec<String> = vec![
        "Auto".into(),
        "Plan".into(),
        "Build".into(),
        "alpha".into(),
        "zeta".into(),
    ];
    assert_eq!(next_primary_in_cycle("Build", &order), "alpha");
    assert_eq!(next_primary_in_cycle("alpha", &order), "zeta");
    // The last user primary wraps back to the front of the cycle.
    assert_eq!(next_primary_in_cycle("zeta", &order), "Auto");
}

#[test]
fn shift_tab_cycle_wraps_through_swarm_back_to_auto() {
    // Regression for the `Shift+Tab` cycle getting stuck on `Swarm`
    // (implementation note): driving the cycle from
    // `Auto` must visit every builtin primary, advance *past* `Swarm`, and
    // wrap back to `Auto` — indefinitely, with no stuck state in either
    // direction of travel.
    let order: Vec<String> = vec!["Auto".into(), "Plan".into(), "Build".into(), "Swarm".into()];
    // One full lap from `Auto`.
    let mut cur = "Auto".to_string();
    let mut visited = Vec::new();
    for _ in 0..order.len() {
        cur = next_primary_in_cycle(&cur, &order);
        visited.push(cur.clone());
    }
    assert_eq!(visited, vec!["Plan", "Build", "Swarm", "Auto"]);
    // The single step the bug broke: leaving `Swarm` advances to the front.
    assert_eq!(next_primary_in_cycle("Swarm", &order), "Auto");
    // And it keeps looping (a second lap is identical — no stuck state).
    let mut cur = "Auto".to_string();
    for expected in ["Plan", "Build", "Swarm", "Auto", "Plan"] {
        cur = next_primary_in_cycle(&cur, &order);
        assert_eq!(cur, expected, "cycle stalled after {cur}");
    }
}

#[test]
fn next_primary_in_cycle_off_cycle_starts_at_front() {
    let order: Vec<String> = vec!["Auto".into(), "Plan".into(), "Build".into()];
    // A subagent / stale name isn't in the cycle — start at the front.
    assert_eq!(next_primary_in_cycle("builder", &order), "Auto");
    // An empty cycle is a no-op (returns the current name unchanged).
    assert_eq!(next_primary_in_cycle("Auto", &[]), "Auto");
}

// ── Per-agent tool-description overrides ────────────────────────────────────

#[test]
fn parse_agent_reads_tool_descriptions_bare_and_per_mode() {
    // Raw string so the YAML indentation is preserved literally (a `\`
    // line-continuation would eat the leading spaces and flatten the map).
    let text = r#"---
description: A custom builder.
mode: primary
tools: [read, task]
tool_descriptions:
  read: "Read the file you will edit yourself."
  task:
    normal: "Delegate substantive work here."
    frontier: "Delegate only when the work is separable."
    defensive: "Hand each well-scoped piece to a subagent in its own context."
---

Body.
"#;
    let def = parse_agent(text, "builder", "x.md".into()).unwrap();
    // Bare string fans out to every mode.
    let read = def.tool_descriptions.get("read").unwrap().to_override();
    assert_eq!(
        read.normal.as_deref(),
        Some("Read the file you will edit yourself.")
    );
    assert_eq!(
        read.defensive.as_deref(),
        Some("Read the file you will edit yourself.")
    );
    assert_eq!(
        read.frontier.as_deref(),
        Some("Read the file you will edit yourself.")
    );
    // Per-mode object maps straight across.
    let task = def.tool_descriptions.get("task").unwrap().to_override();
    assert_eq!(
        task.normal.as_deref(),
        Some("Delegate substantive work here.")
    );
    assert_eq!(
        task.frontier.as_deref(),
        Some("Delegate only when the work is separable.")
    );
    assert_eq!(
        task.defensive.as_deref(),
        Some("Hand each well-scoped piece to a subagent in its own context.")
    );
}

#[test]
fn tool_descriptions_round_trip_through_markdown() {
    let text = r#"---
description: A custom builder.
mode: subagent
tools: [read]
tool_descriptions:
  read: "do-it-yourself wording"
---

Body.
"#;
    let def = parse_agent(text, "builder", "x.md".into()).unwrap();
    // Guard against a vacuous pass (empty == empty): the override is present.
    assert!(!def.tool_descriptions.is_empty());
    let md = def.to_markdown().unwrap();
    let reparsed = parse_agent(&md, "builder", "x.md".into()).unwrap();
    assert_eq!(def.tool_descriptions, reparsed.tool_descriptions);
}

#[test]
fn tool_description_override_for_ungranted_tool_is_rejected() {
    // Overriding a tool the agent doesn't grant is a mistake (inert), so it's
    // rejected loudly rather than silently dropped.
    let text = r#"---
description: d
mode: subagent
tools: [read]
tool_descriptions:
  bash: "nope, not granted"
---
Body.
"#;
    let def = parse_agent(text, "builder", "x.md".into()).unwrap();
    let err = validate_invariants(&def).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("does not grant"), "{msg}");
    assert!(msg.contains("bash"), "{msg}");
}

#[test]
fn tool_description_override_for_unknown_tool_is_rejected() {
    let text = r#"---
description: d
mode: subagent
tools: [read]
tool_descriptions:
  not_a_tool: "x"
---
Body.
"#;
    let def = parse_agent(text, "builder", "x.md".into()).unwrap();
    let err = validate_invariants(&def).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("unknown tool"), "{msg}");
}
