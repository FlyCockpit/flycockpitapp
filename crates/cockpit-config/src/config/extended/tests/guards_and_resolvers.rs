use super::*;

#[test]
fn injection_threshold_defaults_to_off() {
    let cfg = ExtendedConfig::default();
    assert_eq!(
        cfg.prompt_injection_guard.threshold,
        InjectionThreshold::Off
    );
    let parsed: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(
        parsed.prompt_injection_guard.threshold,
        InjectionThreshold::Off
    );
}

#[test]
fn injection_threshold_ordering_and_blocking() {
    use InjectionThreshold::*;
    // Ordering is Off < Low < Medium < High.
    assert!(Off < Low && Low < Medium && Medium < High);

    // `off` threshold never blocks any rating.
    for r in [Low, Medium, High] {
        assert!(!Off.blocks(r), "off must never block {r:?}");
    }
    // Block when rating >= threshold; proceed below.
    assert!(Low.blocks(Low));
    assert!(Low.blocks(Medium));
    assert!(Low.blocks(High));

    assert!(!Medium.blocks(Low));
    assert!(Medium.blocks(Medium));
    assert!(Medium.blocks(High));

    assert!(!High.blocks(Low));
    assert!(!High.blocks(Medium));
    assert!(High.blocks(High));
}

#[test]
fn injection_threshold_parse_and_cycle() {
    assert_eq!(
        InjectionThreshold::parse_level("HIGH"),
        Some(InjectionThreshold::High)
    );
    assert_eq!(
        InjectionThreshold::parse_level("  medium "),
        Some(InjectionThreshold::Medium)
    );
    assert_eq!(InjectionThreshold::parse_level("bogus"), None);
    assert_eq!(InjectionThreshold::Off.cycled(), InjectionThreshold::Low);
    assert_eq!(InjectionThreshold::High.cycled(), InjectionThreshold::Off);
}

#[test]
fn injection_guard_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.prompt_injection_guard.threshold = InjectionThreshold::High;
    cfg.prompt_injection_guard.check_prompt = Some("CUSTOM CHECK".into());
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"threshold\""), "{on_disk}");
    assert!(on_disk.contains("\"high\""), "{on_disk}");
    assert!(on_disk.contains("CUSTOM CHECK"), "{on_disk}");
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let cfg2 = doc2.config();
    assert_eq!(
        cfg2.prompt_injection_guard.threshold,
        InjectionThreshold::High
    );
    assert_eq!(
        cfg2.prompt_injection_guard.check_prompt.as_deref(),
        Some("CUSTOM CHECK")
    );
}

#[test]
fn resolve_injection_guard_project_overrides_global() {
    // Two layers in walk order: global first, then project. The
    // project layer overrides only `threshold`; `check_prompt` is
    // omitted there and must inherit the global value.
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("global-config.json");
    std::fs::write(
        &global,
        r#"{"prompt_injection_guard":{"threshold":"low","check_prompt":"GLOBAL"}}"#,
    )
    .unwrap();
    let project = tmp.path().join("project-config.json");
    std::fs::write(
        &project,
        r#"{"prompt_injection_guard":{"threshold":"high"}}"#,
    )
    .unwrap();

    let resolved = resolve_injection_guard_from_paths(&[global, project]);
    assert_eq!(
        resolved.threshold,
        InjectionThreshold::High,
        "project (later) layer overrides the global threshold"
    );
    assert_eq!(
        resolved.check_prompt, "GLOBAL",
        "an omitted project field inherits the global value"
    );
}

#[test]
fn resolve_injection_guard_global_value_used_when_project_silent() {
    // A single global layer with both fields set, no project layer.
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("config.json");
    std::fs::write(
        &global,
        r#"{"prompt_injection_guard":{"threshold":"medium","check_prompt":"G"}}"#,
    )
    .unwrap();
    let resolved = resolve_injection_guard_from_paths(&[global]);
    assert_eq!(resolved.threshold, InjectionThreshold::Medium);
    assert_eq!(resolved.check_prompt, "G");
}

#[test]
fn resolve_injection_guard_result_action_uses_camel_case_only() {
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("global.json");
    std::fs::write(
        &global,
        r#"{"prompt_injection_guard":{"resultAction":"ask"}}"#,
    )
    .unwrap();

    let resolved = resolve_injection_guard_from_paths(&[global]);

    assert_eq!(resolved.result_action, InjectionResultAction::Ask);
}

#[test]
fn resolve_injection_guard_snake_result_action_fails_closed() {
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("global.json");
    let project = tmp.path().join("project.json");
    std::fs::write(
        &global,
        r#"{"prompt_injection_guard":{"resultAction":"ask"}}"#,
    )
    .unwrap();
    std::fs::write(
        &project,
        r#"{"prompt_injection_guard":{"result_action":"ask"}}"#,
    )
    .unwrap();

    let resolved = resolve_injection_guard_from_paths(&[global, project]);

    assert_eq!(resolved.result_action, InjectionResultAction::Block);
}

#[test]
fn resolve_injection_guard_defaults_when_nothing_on_disk() {
    let tmp = TempDir::new().unwrap();
    let absent = tmp.path().join("does-not-exist.json");
    let resolved = resolve_injection_guard_from_paths(&[absent]);
    assert_eq!(resolved.threshold, InjectionThreshold::Off);
    assert_eq!(resolved.check_prompt, default_injection_check_prompt());
}

#[test]
fn predict_next_message_defaults_to_short_and_parses_all_values() {
    // Default + an omitted field both read `short`.
    assert_eq!(
        ExtendedConfig::default().predict_next_message,
        PredictNextMessage::Short
    );
    let parsed: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(parsed.predict_next_message, PredictNextMessage::Short);
    // All three spellings parse.
    for (json, expect) in [
        (r#"{"predictNextMessage":"off"}"#, PredictNextMessage::Off),
        (
            r#"{"predictNextMessage":"short"}"#,
            PredictNextMessage::Short,
        ),
        (r#"{"predictNextMessage":"long"}"#, PredictNextMessage::Long),
    ] {
        let cfg: ExtendedConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.predict_next_message, expect, "{json}");
    }
}

#[test]
fn predict_next_message_cycles_off_short_long() {
    assert_eq!(PredictNextMessage::Off.cycled(), PredictNextMessage::Short);
    assert_eq!(PredictNextMessage::Short.cycled(), PredictNextMessage::Long);
    assert_eq!(PredictNextMessage::Long.cycled(), PredictNextMessage::Off);
    assert!(!PredictNextMessage::Off.is_enabled());
    assert!(PredictNextMessage::Short.is_enabled());
    assert!(PredictNextMessage::Long.is_enabled());
}

#[test]
fn predict_next_message_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.predict_next_message = PredictNextMessage::Long;
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"predictNextMessage\""), "{on_disk}");
    assert!(on_disk.contains("long"), "{on_disk}");
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    assert_eq!(doc2.config().predict_next_message, PredictNextMessage::Long);
}

// ── Harness config (external-harness-tool) ───────────────────────

#[test]
fn harness_prompt_input_defaults_to_stdin() {
    // The argv-cap-proof default: a harness entry that omits
    // `prompt_input` parses as `stdin`.
    let json = r#"{"command": "x"}"#;
    let hc: HarnessConfig = serde_json::from_str(json).unwrap();
    assert_eq!(hc.prompt_input, PromptInputMode::Stdin);
    assert_eq!(hc.argv_overflow, ArgvOverflowBehavior::SpillToTempfile);
    assert_eq!(hc.timeout_secs, DEFAULT_HARNESS_TIMEOUT_SECS);
    assert!(hc.models.is_empty());
    assert!(!hc.supports_json_output);
}

#[test]
fn harness_config_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    for wanted in ["claude", "grok"] {
        let (name, preset) = builtin_harness_presets()
            .into_iter()
            .find(|(n, _)| n == wanted)
            .unwrap();
        cfg.harnesses.insert(name, preset);
    }
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"harnesses\""), "{on_disk}");
    assert!(on_disk.contains("\"claude\""), "{on_disk}");
    assert!(on_disk.contains("\"grok\""), "{on_disk}");
    assert!(on_disk.contains("bypassPermissions"), "{on_disk}");
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let cfg2 = doc2.config();
    let claude = cfg2.harnesses.get("claude").unwrap();
    assert_eq!(claude.command, "claude");
    assert!(claude.supports_json_output);
    assert_eq!(claude.prompt_input, PromptInputMode::Stdin);
    let grok = cfg2.harnesses.get("grok").unwrap();
    assert_eq!(grok.command, "grok");
    assert_eq!(grok.prompt_input, PromptInputMode::Tempfile);
    assert_eq!(
        grok.args,
        vec![
            "--prompt-file".to_string(),
            "{prompt}".to_string(),
            "--permission-mode".to_string(),
            "bypassPermissions".to_string()
        ]
    );
}

#[test]
fn shell_compression_defaults_enabled() {
    // A missing `shellCompression` field parses as Enabled (the default).
    let cfg: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(cfg.shell_compression, ShellCompression::Enabled);
    assert!(cfg.shell_compression.is_enabled());
    assert!(ExtendedConfig::default().shell_compression.is_enabled());
}

#[test]
fn shell_compression_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    assert_eq!(cfg.shell_compression, ShellCompression::Enabled);
    cfg.shell_compression = ShellCompression::Disabled;
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"shellCompression\""), "{on_disk}");
    assert!(on_disk.contains("\"disabled\""), "{on_disk}");
    let cfg2 = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(cfg2.shell_compression, ShellCompression::Disabled);
}

#[test]
fn trusted_only_defaults_off_and_round_trips_through_extended_doc() {
    let cfg: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert!(!cfg.trusted_only);
    assert!(!ExtendedConfig::default().trusted_only);

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.trusted_only = true;
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"trustedOnly\""), "{on_disk}");
    let cfg2 = ExtendedConfigDoc::load(&path).unwrap().config();
    assert!(cfg2.trusted_only);
}

#[test]
fn shell_compression_toggled_flips() {
    assert_eq!(
        ShellCompression::Enabled.toggled(),
        ShellCompression::Disabled
    );
    assert_eq!(
        ShellCompression::Disabled.toggled(),
        ShellCompression::Enabled
    );
    // serde lowercase spelling is the on-disk form.
    assert_eq!(
        serde_json::to_value(ShellCompression::Enabled).unwrap(),
        serde_json::json!("enabled")
    );
    assert_eq!(
        serde_json::to_value(ShellCompression::Disabled).unwrap(),
        serde_json::json!("disabled")
    );
}

#[test]
fn builtin_presets_are_verified_and_well_formed() {
    let presets = builtin_harness_presets();
    // The verified set ships claude/codex/opencode/copilot/goose/grok.
    let names: Vec<&str> = presets.iter().map(|(n, _)| n.as_str()).collect();
    for expected in ["claude", "codex", "opencode", "copilot", "goose", "grok"] {
        assert!(names.contains(&expected), "missing preset `{expected}`");
    }
    for (name, hc) in &presets {
        assert!(
            !name.ends_with("-cli"),
            "preset `{name}` must use the external CLI executable name, not a -cli alias"
        );
        assert_eq!(
            name, &hc.command,
            "preset `{name}` id must match its external CLI executable"
        );
        assert!(!hc.command.is_empty(), "`{name}` has empty command");
        // Every preset advertising JSON output supplies the flags.
        if hc.supports_json_output {
            assert!(
                !hc.json_output_args.is_empty(),
                "`{name}` claims JSON output but has no json_output_args"
            );
        }
        // An agent-file-capable preset supplies the flag template.
        if hc.supports_agent_file {
            assert!(
                hc.agent_file_args
                    .iter()
                    .any(|a| a.contains("{agent_file}")),
                "`{name}` claims agent-file support but has no {{agent_file}} template"
            );
        }
    }
    // copilot is argv-only ⇒ overflow must be `error` (spilling a path
    // as the prompt would silently break the run).
    let copilot = &presets.iter().find(|(n, _)| n == "copilot").unwrap().1;
    assert_eq!(copilot.prompt_input, PromptInputMode::Argv);
    assert_eq!(copilot.argv_overflow, ArgvOverflowBehavior::Error);
    // opencode's model-list probe is wired.
    let opencode = &presets.iter().find(|(n, _)| n == "opencode").unwrap().1;
    assert_eq!(opencode.model_list_args, vec!["models".to_string()]);
    // grok uses prompt files for large-prompt safety and static models
    // because `grok models` is human-formatted, not one id per line.
    let grok = &presets.iter().find(|(n, _)| n == "grok").unwrap().1;
    assert_eq!(grok.prompt_input, PromptInputMode::Tempfile);
    assert_eq!(
        grok.args,
        vec![
            "--prompt-file".to_string(),
            "{prompt}".to_string(),
            "--permission-mode".to_string(),
            "bypassPermissions".to_string()
        ]
    );
    assert_eq!(
        grok.model_args,
        vec!["-m".to_string(), "{model}".to_string()]
    );
    assert_eq!(
        grok.json_output_args,
        vec!["--output-format".to_string(), "json".to_string()]
    );
    assert_eq!(
        grok.agent_file_args,
        vec!["--agent".to_string(), "{agent_file}".to_string()]
    );
    assert!(grok.model_list_args.is_empty());
    assert_eq!(grok.default_model.as_deref(), Some("grok-build"));
    assert_eq!(grok.models, vec!["grok-build".to_string()]);
}

#[test]
fn resolve_harnesses_deep_merges_per_field() {
    // Two layers: the global defines a full `claude` harness; the
    // project overrides ONLY `default_model`. Deep-merge must keep the
    // global's command/args while taking the project's model.
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("global.json");
    let project = tmp.path().join("project.json");
    std::fs::write(
            &global,
            r#"{"harnesses":{"claude":{"command":"claude","args":["-p"],"supports_json_output":true,"default_model":"opus"}}}"#,
        )
        .unwrap();
    std::fs::write(
        &project,
        r#"{"harnesses":{"claude":{"default_model":"sonnet"}}}"#,
    )
    .unwrap();
    // Walk order: global (least-specific) first, project last.
    let merged = resolve_harnesses_from_paths(&[global, project]);
    let claude = merged.get("claude").expect("claude survives merge");
    // Project field wins…
    assert_eq!(claude.default_model.as_deref(), Some("sonnet"));
    // …without dropping the inherited fields.
    assert_eq!(claude.command, "claude");
    assert_eq!(claude.args, vec!["-p".to_string()]);
    assert!(claude.supports_json_output);
}

#[test]
fn resolve_harnesses_unions_distinct_names_and_skips_garbage() {
    let tmp = TempDir::new().unwrap();
    let a = tmp.path().join("a.json");
    let b = tmp.path().join("b.json");
    std::fs::write(&a, r#"{"harnesses":{"claude":{"command":"claude"}}}"#).unwrap();
    // `bad` is missing the required `command` → dropped, not a crash;
    // `codex` parses fine.
    std::fs::write(
        &b,
        r#"{"harnesses":{"codex":{"command":"codex"},"bad":{"args":["x"]}}}"#,
    )
    .unwrap();
    let merged = resolve_harnesses_from_paths(&[a, b]);
    assert!(merged.contains_key("claude"));
    assert!(merged.contains_key("codex"));
    assert!(!merged.contains_key("bad"), "unparseable entry dropped");
}

/// `gitignore_allow` resolves as a de-duplicated **union** across layers in
/// walk order — not a more-specific-wins override (it's a list-valued
/// field like skills `scan_dirs`).
#[test]
fn resolve_gitignore_allow_unions_layers_dedup() {
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("global.json");
    let project = tmp.path().join("project.json");
    std::fs::write(&global, r#"{"gitignore_allow":["target/","*.lock"]}"#).unwrap();
    // Project adds `dist/**` and repeats `target/` (deduped) + a blank
    // (dropped).
    std::fs::write(&project, r#"{"gitignore_allow":["target/","dist/**",""]}"#).unwrap();
    let merged = resolve_gitignore_allow_from_paths(&[global, project]);
    assert_eq!(
        merged,
        vec![
            "target/".to_string(),
            "*.lock".to_string(),
            "dist/**".to_string()
        ]
    );
}

#[test]
fn resolve_redact_list_unions_layers_dedup_and_trim() {
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("global.json");
    let project = tmp.path().join("project.json");
    std::fs::write(
        &global,
        r#"{
                "redact": {
                    "denylist": ["AKIA_HOME", "dup"],
                    "allowlist": ["PATH", " HOME_ONLY "],
                    "extra_dotenv_paths": ["../shared/.env.ci", "dup.env"]
                }
            }"#,
    )
    .unwrap();
    std::fs::write(
        &project,
        r#"{
                "redact": {
                    "denylist": ["dup", "proj-tok", "", " "],
                    "allowlist": ["HOME_ONLY", "PROJECT_ONLY", ""],
                    "extra_dotenv_paths": ["dup.env", "project.env", ""]
                }
            }"#,
    )
    .unwrap();

    let merged = resolve_redact_list_unions_from_paths(&[global, project]);

    assert_eq!(
        merged.denylist,
        vec![
            "AKIA_HOME".to_string(),
            "dup".to_string(),
            "proj-tok".to_string()
        ]
    );
    assert_eq!(
        merged.allowlist,
        vec![
            "PATH".to_string(),
            "HOME_ONLY".to_string(),
            "PROJECT_ONLY".to_string()
        ]
    );
    assert_eq!(
        merged.extra_dotenv_paths,
        vec![
            PathBuf::from("../shared/.env.ci"),
            PathBuf::from("dup.env"),
            PathBuf::from("project.env"),
        ],
        "relative paths are preserved verbatim and deduped by PathBuf equality"
    );
}

#[test]
fn resolve_redact_list_unions_skips_malformed_layers() {
    let tmp = TempDir::new().unwrap();
    let global = tmp.path().join("global.json");
    let project = tmp.path().join("project.json");
    std::fs::write(
        &global,
        r#"{"redact":{"denylist":["home-secret"],"allowlist":["HOME_OK"]}}"#,
    )
    .unwrap();
    std::fs::write(&project, r#"{"redact":{"denylist":["unterminated"]}"#).unwrap();

    let merged = resolve_redact_list_unions_from_paths(&[global, project]);

    assert_eq!(merged.denylist, vec!["home-secret".to_string()]);
    assert_eq!(merged.allowlist, vec!["HOME_OK".to_string()]);
    assert!(merged.extra_dotenv_paths.is_empty());
}

#[test]
fn load_for_cwd_unions_redact_lists_and_keeps_dotenv_patterns_replace() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let home_cfg = tmp.path().join("home/.config/cockpit/config.json");
    std::fs::create_dir_all(home_cfg.parent().unwrap()).unwrap();
    std::fs::write(
        &home_cfg,
        r#"{
                "redact": {
                    "denylist": ["home-secret"],
                    "allowlist": ["HOME_OK"],
                    "extra_dotenv_paths": ["home.env"],
                    "dotenv_patterns": [".env.home"]
                }
            }"#,
    )
    .unwrap();
    let project = tmp.path().join("repo");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    std::fs::write(
        project.join(".cockpit/config.json"),
        r#"{
                "redact": {
                    "denylist": ["project-secret"],
                    "allowlist": ["PROJECT_OK"],
                    "extra_dotenv_paths": ["project.env"],
                    "dotenv_patterns": [".env.project"]
                }
            }"#,
    )
    .unwrap();

    let cfg = load_for_cwd(&project);

    assert_eq!(
        cfg.redact.denylist,
        vec!["home-secret".to_string(), "project-secret".to_string()]
    );
    assert_eq!(
        cfg.redact.allowlist,
        vec!["HOME_OK".to_string(), "PROJECT_OK".to_string()]
    );
    assert_eq!(
        cfg.redact.extra_dotenv_paths,
        vec![PathBuf::from("home.env"), PathBuf::from("project.env")]
    );
    assert_eq!(
        cfg.redact.dotenv_patterns,
        vec![".env.project".to_string()],
        "dotenv_patterns remains a most-specific-wins replace field"
    );
}

/// Round-trips `gitignore_allow` through the doc, and clearing the list
/// persists (the field is always serialized, like the other editable
/// string-lists).
#[test]
fn gitignore_allow_round_trips_and_clears() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    assert!(cfg.gitignore_allow.is_empty());
    cfg.gitignore_allow.push("target/".to_string());
    doc.write(&cfg).unwrap();
    let reloaded = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(reloaded.gitignore_allow, vec!["target/".to_string()]);

    // Clearing the list persists as an empty list.
    let mut doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg2 = doc2.config();
    cfg2.gitignore_allow.clear();
    doc2.write(&cfg2).unwrap();
    let after = ExtendedConfigDoc::load(&path).unwrap().config();
    assert!(after.gitignore_allow.is_empty(), "cleared list persists");
}

/// `append_gitignore_allow_to_project` adds to the nearest project
/// `.cockpit/config.json`, de-duplicates, and preserves sibling keys.
#[test]
fn append_gitignore_allow_targets_project_and_dedups() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path().join("proj");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    let cfg_path = project.join(".cockpit/config.json");
    std::fs::write(&cfg_path, r#"{"name":"Chris"}"#).unwrap();

    append_gitignore_allow_to_project(&project, "target/").unwrap();
    append_gitignore_allow_to_project(&project, "target/").unwrap(); // dup no-op
    append_gitignore_allow_to_project(&project, "dist/**").unwrap();

    let cfg = ExtendedConfigDoc::load(&cfg_path).unwrap().config();
    assert_eq!(
        cfg.gitignore_allow,
        vec!["target/".to_string(), "dist/**".to_string()]
    );
    // Sibling key preserved.
    assert_eq!(cfg.name.as_deref(), Some("Chris"));
}

/// `hintToolCallCorrections` defaults to `false` (absent in config) and
/// round-trips its camelCase serde name when set
/// (implementation note).
#[test]
fn hint_tool_call_corrections_global_default_and_rename() {
    // Absent → false (silent repair, as before).
    let cfg: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert!(!cfg.hint_tool_call_corrections);
    assert!(!ExtendedConfig::default().hint_tool_call_corrections);
    // Present (camelCase) → honored.
    let on: ExtendedConfig = serde_json::from_str(r#"{"hintToolCallCorrections":true}"#).unwrap();
    assert!(on.hint_tool_call_corrections);
    // Serializes under the camelCase key.
    let json = serde_json::to_string(&on).unwrap();
    assert!(json.contains("\"hintToolCallCorrections\":true"));
}

/// `textEmbeddedRecovery` defaults to `available` (absent in config) and
/// round-trips its camelCase serde name + lowercase value
/// (implementation note).
#[test]
fn text_embedded_recovery_global_default_and_rename() {
    // Absent → `available` (the default — recover only known tools).
    let cfg: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(cfg.text_embedded_recovery, TextEmbeddedRecovery::Available);
    assert_eq!(
        ExtendedConfig::default().text_embedded_recovery,
        TextEmbeddedRecovery::Available
    );
    // Present (camelCase key, lowercase value) → honored, for all variants.
    for (raw, want) in [
        ("strict", TextEmbeddedRecovery::Strict),
        ("off", TextEmbeddedRecovery::Off),
        ("available", TextEmbeddedRecovery::Available),
    ] {
        let c: ExtendedConfig =
            serde_json::from_str(&format!(r#"{{"textEmbeddedRecovery":"{raw}"}}"#)).unwrap();
        assert_eq!(c.text_embedded_recovery, want);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains(&format!("\"textEmbeddedRecovery\":\"{raw}\"")));
    }
}

/// The `/settings` row cycle: available → strict → off → available.
#[test]
fn text_embedded_recovery_cycles() {
    let mut m = TextEmbeddedRecovery::Available;
    m = m.cycled();
    assert_eq!(m, TextEmbeddedRecovery::Strict);
    m = m.cycled();
    assert_eq!(m, TextEmbeddedRecovery::Off);
    m = m.cycled();
    assert_eq!(m, TextEmbeddedRecovery::Available);
}

#[test]
fn intel_centrality_ranking_defaults_on_and_renames() {
    // Absent → true (default-on; additive signal can't reduce recall).
    let cfg: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert!(cfg.intel_centrality_ranking);
    assert!(ExtendedConfig::default().intel_centrality_ranking);
    // Present (camelCase) → honored.
    let off: ExtendedConfig = serde_json::from_str(r#"{"intelCentralityRanking":false}"#).unwrap();
    assert!(!off.intel_centrality_ranking);
    let json = serde_json::to_string(&off).unwrap();
    assert!(json.contains("\"intelCentralityRanking\":false"));
}

#[test]
fn centrality_ranking_resolves_layered_project_wins() {
    let home = TempDir::new().unwrap();
    let proj = TempDir::new().unwrap();
    let home_cfg = home.path().join("config.json");
    let proj_cfg = proj.path().join("config.json");

    // No layer sets it → default on.
    assert!(resolve_centrality_ranking_from_paths(&[]));

    // Home disables it; with only home present it is off.
    std::fs::write(&home_cfg, r#"{"intelCentralityRanking":false}"#).unwrap();
    assert!(!resolve_centrality_ranking_from_paths(
        std::slice::from_ref(&home_cfg)
    ));

    // Project (later in walk order) re-enables it — project wins.
    std::fs::write(&proj_cfg, r#"{"intelCentralityRanking":true}"#).unwrap();
    assert!(resolve_centrality_ranking_from_paths(&[
        home_cfg.clone(),
        proj_cfg.clone()
    ]));

    // A project layer that OMITS the key leaves the home value intact.
    std::fs::write(&proj_cfg, r#"{"name":"x"}"#).unwrap();
    assert!(!resolve_centrality_ranking_from_paths(&[
        home_cfg, proj_cfg
    ]));
}
