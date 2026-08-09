use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

fn enter_trusted_workspace(
    root: &std::path::Path,
) -> crate::config::trust::ThreadWorkspaceTrustGuard {
    crate::config::trust::enter_workspace_trust_policy(crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(root).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    })
}

fn trusted_load_for_cwd(root: &std::path::Path) -> ExtendedConfig {
    let _trust = enter_trusted_workspace(root);
    load_for_cwd(root)
}

#[test]
fn extended_replacement_is_invisible_until_commit_and_drop_preserves_destination() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, b"{\"name\":\"before\"}\n").unwrap();
    let replacement = b"{\n  \"name\": \"after\"\n}\n";

    let prepared = crate::config::files::prepare_atomic_write(&path, replacement).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"{\"name\":\"before\"}\n");
    drop(prepared);
    assert_eq!(std::fs::read(&path).unwrap(), b"{\"name\":\"before\"}\n");
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);

    let prepared = crate::config::files::prepare_atomic_write(&path, replacement).unwrap();
    prepared.commit().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), replacement);
    assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 1);
}

#[test]
fn extended_write_reloads_sibling_fields_inside_mutation_lock() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, r#"{"future":{"version":1}}"#).unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.name = Some("updated".to_string());

    std::fs::write(
        &path,
        r#"{"future":{"version":2},"tui":{"thinking":"verbose"}}"#,
    )
    .unwrap();
    doc.write(&cfg).unwrap();

    let raw: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(raw["future"]["version"], 2);
    assert_eq!(raw["tui"]["thinking"], "verbose");
    assert_eq!(raw["name"], "updated");
}

#[test]
fn raw_path_removal_reloads_and_preserves_concurrent_sibling_mutation() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{"future":{"version":1},"tui":{"vim_mode":"enabled","thinking":"verbose"}}"#,
    )
    .unwrap();
    let mut stale = ExtendedConfigDoc::load(&path).unwrap();

    std::fs::write(
        &path,
        r#"{"future":{"version":2},"tui":{"vim_mode":"enabled","thinking":"verbose"}}"#,
    )
    .unwrap();
    assert!(
        stale
            .remove_raw_path_and_save(&["tui", "vim_mode"])
            .unwrap()
    );

    let raw: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(raw["future"]["version"], 2);
    assert!(raw["tui"].get("vim_mode").is_none());
    assert_eq!(raw["tui"]["thinking"], "verbose");
}

#[cfg(unix)]
#[test]
fn extended_write_repairs_product_owned_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = TempDir::new().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let config_dir = tmp.path().join("home/.cockpit");
    std::fs::create_dir(&config_dir).unwrap();
    let path = config_dir.join("config.json");
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.name = Some("private".to_string());
    doc.write(&cfg).unwrap();

    assert_eq!(
        std::fs::metadata(config_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn extended_write_preserves_explicit_shared_parent_permissions() {
    use std::os::unix::fs::PermissionsExt as _;

    let tmp = TempDir::new().unwrap();
    let env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let shared = tmp.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = shared.join("cockpit.json");
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    env.set_cockpit_config(&path);

    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.name = Some("private file".to_string());
    doc.write(&cfg).unwrap();

    assert_eq!(
        std::fs::metadata(shared).unwrap().permissions().mode() & 0o777,
        0o755
    );
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn skills_write_approval_defaults_on() {
    assert!(SkillsConfig::default().write_approval);
    assert!(
        serde_json::from_str::<SkillsConfig>("{}")
            .unwrap()
            .write_approval
    );
    assert!(
        !serde_json::from_str::<SkillsConfig>(r#"{"write_approval": false}"#)
            .unwrap()
            .write_approval
    );
}

#[test]
fn goal_verification_defaults_and_sparse_write_round_trip() {
    let default = GoalVerificationConfig::default();
    assert!(default.enabled_for_token_budget(Some(100)));
    assert!(!default.enabled_for_token_budget(None));
    assert_eq!(
        default.effective_skeptic_count(),
        DEFAULT_GOAL_VERIFICATION_SKEPTIC_COUNT
    );
    assert_eq!(
        default.effective_max_rounds(),
        DEFAULT_GOAL_VERIFICATION_MAX_ROUNDS
    );

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = ExtendedConfig::default();
    cfg.goal_verification.enabled = false;
    cfg.goal_verification.skeptic_count = 5;
    cfg.goal_verification.skeptic_model = Some("provider:model".into());
    cfg.goal_verification.max_rounds = 4;
    doc.write(&cfg).unwrap();

    let reloaded = ExtendedConfigDoc::load(&path).unwrap().config();
    assert!(!reloaded.goal_verification.enabled);
    assert_eq!(reloaded.goal_verification.skeptic_count, 5);
    assert_eq!(
        reloaded.goal_verification.skeptic_model.as_deref(),
        Some("provider:model")
    );
    assert_eq!(reloaded.goal_verification.max_rounds, 4);
}

/// Consolidation (GOALS §2a): a single `config.json` holding BOTH
/// layer-wide provider metadata AND the former-`ExtendedConfig` keys must
/// deserialize cleanly through each loader — neither rejects the
/// other's keys, and a round-trip write through one preserves the
/// other's keys verbatim.
#[test]
fn malformed_unrelated_extended_field_does_not_hide_harnesses_or_unknown_raw_keys() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
                "harnesses": {
                    "codex": {
                        "command": "codex",
                        "args": ["exec", "-"]
                    }
                },
                "tui": "not an object",
                "future_key": { "preserve": true }
            }"#,
    )
    .unwrap();

    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    assert_eq!(cfg.harnesses.get("codex").unwrap().command, "codex");
    cfg.name = Some("Updated".into());
    doc.write(&cfg).unwrap();

    let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(raw["future_key"]["preserve"], true);
    let reloaded = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(reloaded.harnesses.get("codex").unwrap().command, "codex");
    assert_eq!(reloaded.name.as_deref(), Some("Updated"));
}

#[test]
fn fully_populated_config_json_round_trips_byte_identically() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    let (harness_name, harness) = builtin_harness_presets().remove(0);

    let mut cfg = ExtendedConfig::default();
    cfg.harnesses.insert(harness_name, harness);
    cfg.agent_guidance_files = vec!["AGENTS.md".into(), "TEAM.md".into()];
    cfg.concurrency = Concurrency::Fork;
    cfg.agent_dirs = vec![PathBuf::from("agents"), PathBuf::from("~/agents")];
    cfg.gitignore_allow = vec!["target/generated/**".into()];
    cfg.redact.denylist = vec!["literal-secret".into()];
    cfg.redact.allowlist = vec!["SAFE_TOKEN".into()];
    cfg.redact.extra_dotenv_paths = vec![PathBuf::from("secrets/.env")];
    cfg.tui.vim_mode = VimModeSetting::Enabled;
    cfg.tui.thinking = ThinkingDisplay::Verbose;
    cfg.tui.render_user_markdown = true;
    cfg.tui.banner.enabled = false;
    cfg.tui.diff_style = DiffStyle::Inline;
    cfg.tui.exit_tail_lines = 42;
    cfg.tui.use_emojis = true;
    cfg.tui.caffeinate_display_awake = true;
    cfg.name = Some("Config Roundtrip".into());
    cfg.packages_directory = Some(PathBuf::from("packages-cache"));
    cfg.tools.insert(
        "webfetch".into(),
        ToolCommandTemplate {
            enabled: true,
            command: "curl -sSL {url}".into(),
            description: Some("Fetch a URL".into()),
        },
    );
    cfg.web = WebConfig {
        provider: WebProvider::Tinyfish,
        firecrawl_base_url: Some("https://firecrawl.test".into()),
        firecrawl_notice_acknowledged: false,
        custom: WebCustomConfig {
            fetch_command: Some("custom-fetch {url}".into()),
            search_command: Some("custom-search {query}".into()),
        },
    };
    cfg.allow_remote_config = true;
    cfg.utility_model = Some("openai:gpt-5.5".into());
    cfg.translation_model = Some("openai:gpt-5.5-mini".into());
    cfg.cheap_code = Some("openai:gpt-5.5-mini".into());
    cfg.smart_code = Some("anthropic:claude-sonnet-4-7".into());
    cfg.reasoning = Some("anthropic:claude-opus-4-7".into());
    cfg.agent_chooses_subagent_model = true;
    cfg.auto_title = Some("openai:gpt-5.5-mini".into());
    cfg.skill_injection = Some("openai:gpt-5.5-mini".into());
    cfg.predict_next_message_model = Some("openai:gpt-5.5-mini".into());
    cfg.harness_report_summarization = Some("openai:gpt-5.5-mini".into());
    cfg.compact_model = Some("openai:gpt-5.5".into());
    cfg.compact_prompt = Some("Summarize exactly.".into());
    cfg.prompt_injection_guard = PromptInjectionGuardConfig {
        model: Some("openai:gpt-5.5-mini".into()),
        threshold: InjectionThreshold::Low,
        result_action: InjectionResultAction::Ask,
        check_prompt: Some("Check this prompt.".into()),
    };
    cfg.preflight = PreflightConfig {
        enabled: true,
        model: Some("openai:gpt-5.5-mini".into()),
        preflight_prompt: Some("Rewrite briefly.".into()),
    };
    cfg.system_prompt.time_injection_interval_minutes = 9;
    cfg.schedule.max_concurrent = 3;
    cfg.schedule.allow_unbounded_loops = true;
    cfg.resource_scheduler.enabled = true;
    cfg.resource_scheduler.pools.cpu.capacity = 2;
    cfg.resource_scheduler.pools.memory.capacity = 3;
    cfg.resource_scheduler
        .rules
        .push(ResourceSchedulerRuleConfig {
            program: Some("cargo".into()),
            subcommand: Some("test".into()),
            approval_key: Some("cargo test".into()),
            regex: None,
            resources: std::collections::BTreeMap::from([("cpu".into(), 1)]),
        });
    cfg.daemon.uploads = DaemonUploadLimitsConfig {
        per_client_uploads: 2,
        global_uploads: 8,
        per_upload_bytes: 1024,
        global_bytes: 8192,
    };
    cfg.retention = RetentionConfig {
        payload_window_days: 14,
        session_window_days: 30,
        sweep_interval_hours: 12,
        vacuum_min_deletions: 10,
        vacuum_interval_days: 2,
    };
    cfg.delegation.max_parallel = 2;
    cfg.delegation.default_recursion_depth = 1;
    cfg.delegation.recursion.insert(
        "Build".into(),
        DelegationRecursionPolicy {
            allowed_targets: vec!["Plan".into()],
            default_depth: Some(1),
            max_depth: Some(2),
        },
    );
    cfg.deepthink.enabled = true;
    cfg.review.default_participants = vec!["scout".into(), "critic".into()];
    cfg.lsp.enabled = true;
    cfg.lsp.auto_install = LspAutoInstall::On;
    cfg.loop_guard.repeat_threshold = 3;
    cfg.max_primary_rounds = 12;
    cfg.dialog.lockout_ms = 25;
    cfg.skills.scan_dirs = vec!["./skills".into()];
    cfg.skills.auto_bang_commands = true;
    cfg.skills.ancestor_walk = true;
    cfg.llm_mode = LlmMode::Frontier;
    cfg.default_primary_agent = DefaultPrimaryAgent::Plan;
    cfg.translation.user_language = "de".into();
    cfg.translation.model_language = "en".into();
    cfg.default_approval_mode = ApprovalMode::Auto;
    cfg.approval_policy
        .risk_max_scope
        .insert("medium".into(), ApprovalPolicyScope::Project);
    cfg.predict_next_message = PredictNextMessage::Long;
    cfg.shell_compression = ShellCompression::Disabled;
    cfg.inline_think = false;
    cfg.hint_tool_call_corrections = true;
    cfg.text_embedded_recovery = TextEmbeddedRecovery::Strict;
    cfg.intel_centrality_ranking = false;

    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    doc.write(&cfg).unwrap();

    let mut canonical = ExtendedConfigDoc::load(&path).unwrap();
    let cfg = canonical.config();
    canonical.write(&cfg).unwrap();
    let before = std::fs::read(&path).unwrap();

    let mut reloaded = ExtendedConfigDoc::load(&path).unwrap();
    let cfg = reloaded.config();
    reloaded.write(&cfg).unwrap();
    let after = std::fs::read(&path).unwrap();

    assert_eq!(after, before);
}

#[test]
fn command_resource_profiles_round_trip_generic_shape_and_unknowns() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
            &path,
            r#"{
                "commandResourceProfiles": {
                    "profiles": {
                        "terraform_toolchain": {
                            "commands": ["terraform", "tofu"],
                            "roots": [
                                { "kind": "terraform_plugin_cache", "env": "TF_PLUGIN_CACHE_DIR", "access": "read_write", "futureRoot": true }
                            ],
                            "futureProfile": { "preserve": true }
                        }
                    },
                    "wrappers": {
                        "just ci": ["rust_toolchain", "node_package_manager"],
                        "just infra-plan": ["terraform_toolchain"]
                    },
                    "enabled": {
                        "rust_toolchain": false,
                        "future_profile": true
                    },
                    "futureTop": { "keep": true }
                },
                "future_key": true
            }"#,
        )
        .unwrap();

    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    assert_eq!(
        cfg.command_resource_profiles.wrappers["just ci"],
        vec![
            "rust_toolchain".to_string(),
            "node_package_manager".to_string()
        ]
    );
    assert_eq!(
        cfg.command_resource_profiles.profiles["terraform_toolchain"].commands,
        vec!["terraform".to_string(), "tofu".to_string()]
    );
    assert!(
        !cfg.command_resource_profiles
            .profile_enabled("rust_toolchain")
    );
    assert!(
        cfg.command_resource_profiles
            .profile_enabled("node_package_manager")
    );

    cfg.command_resource_profiles
        .wrappers
        .insert("make check".to_string(), vec!["go_toolchain".to_string()]);
    doc.write(&cfg).unwrap();

    let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(raw["future_key"], true);
    assert_eq!(raw["commandResourceProfiles"]["futureTop"]["keep"], true);
    assert_eq!(
        raw["commandResourceProfiles"]["profiles"]["terraform_toolchain"]["futureProfile"]["preserve"],
        true
    );
    assert_eq!(
        raw["commandResourceProfiles"]["profiles"]["terraform_toolchain"]["roots"][0]["futureRoot"],
        true
    );
    assert_eq!(
        raw["commandResourceProfiles"]["wrappers"]["make check"][0],
        "go_toolchain"
    );
    let reloaded = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(
        reloaded.command_resource_profiles.wrappers["just infra-plan"],
        vec!["terraform_toolchain".to_string()]
    );
}

#[test]
fn command_resource_profiles_reject_legacy_rust_toolchain_key() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
                "commandResourceProfiles": {
                    "rustToolchain": ["just test"]
                }
            }"#,
    )
    .unwrap();

    let (_cfg, warnings) = ExtendedConfigDoc::load(&path)
        .unwrap()
        .config_with_warnings();

    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("commandResourceProfiles")),
        "{warnings:?}"
    );
}

#[test]
fn malformed_data_syntax_section_warns_and_uses_defaults() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, r#"{"data_syntax":"not an object"}"#).unwrap();

    let (cfg, warnings) = ExtendedConfigDoc::load(&path)
        .unwrap()
        .config_with_warnings();

    assert!(cfg.data_syntax.enabled);
    assert_eq!(cfg.data_syntax.max_bytes, 10 * 1024 * 1024);
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("data_syntax")),
        "{warnings:?}"
    );
}

#[test]
fn resource_scheduler_defaults_enabled_with_builtin_pools() {
    let cfg: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert!(cfg.resource_scheduler.enabled);
    assert_eq!(
        cfg.resource_scheduler.pools.cpu.capacity,
        DEFAULT_RESOURCE_POOL_CAPACITY
    );
    assert_eq!(
        cfg.resource_scheduler.pools.memory.capacity,
        DEFAULT_RESOURCE_POOL_CAPACITY
    );
    assert_eq!(
        cfg.resource_scheduler.limits.max_queued,
        DEFAULT_RESOURCE_SCHEDULER_MAX_QUEUED
    );
}

#[test]
fn resource_scheduler_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
                "resourceScheduler": {
                    "enabled": false,
                    "pools": {
                        "cpu": { "capacity": 3 },
                        "memory": { "capacity": 4 },
                        "gpu": { "capacity": 1 }
                    },
                    "limits": { "maxQueued": 7 },
                    "rules": [
                        {
                            "approvalKey": "cargo test",
                            "regex": "cargo test",
                            "resources": { "cpu": 2, "memory": 1 }
                        }
                    ]
                },
                "future_key": true
            }"#,
    )
    .unwrap();

    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    assert!(!cfg.resource_scheduler.enabled);
    assert_eq!(cfg.resource_scheduler.pools.cpu.capacity, 3);
    assert_eq!(cfg.resource_scheduler.pools.memory.capacity, 4);
    assert_eq!(
        cfg.resource_scheduler
            .pools
            .other
            .get("gpu")
            .map(|pool| pool.capacity),
        Some(1)
    );
    assert_eq!(cfg.resource_scheduler.limits.max_queued, 7);
    assert_eq!(cfg.resource_scheduler.rules.len(), 1);
    assert_eq!(
        cfg.resource_scheduler.rules[0].resources.get("cpu"),
        Some(&2)
    );

    cfg.resource_scheduler.enabled = true;
    cfg.resource_scheduler.pools.cpu.capacity = 2;
    doc.write(&cfg).unwrap();

    let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(raw["future_key"], true);
    assert_eq!(raw["resourceScheduler"]["enabled"], true);
    assert_eq!(raw["resourceScheduler"]["pools"]["cpu"]["capacity"], 2);
    assert_eq!(raw["resourceScheduler"]["pools"]["memory"]["capacity"], 4);
    assert_eq!(raw["resourceScheduler"]["pools"]["gpu"]["capacity"], 1);
    assert_eq!(raw["resourceScheduler"]["limits"]["maxQueued"], 7);
    assert_eq!(
        raw["resourceScheduler"]["rules"][0]["approvalKey"],
        "cargo test"
    );
}

#[test]
fn utility_sub_roles_fall_back_to_utility_then_session_none() {
    let mut cfg = ExtendedConfig {
        utility_model: Some("p:utility".into()),
        auto_title: Some("p:title".into()),
        skill_injection: Some("p:skills".into()),
        predict_next_message_model: Some("p:predict".into()),
        harness_report_summarization: Some("p:harness".into()),
        ..ExtendedConfig::default()
    };
    cfg.prompt_injection_guard.model = Some("p:guard".into());
    cfg.preflight.model = Some("p:preflight".into());

    assert_eq!(cfg.auto_title_model_ref(), Some("p:title"));
    assert_eq!(cfg.guard_model_ref(), Some("p:guard"));
    assert_eq!(cfg.skill_injection_model_ref(), Some("p:skills"));
    assert_eq!(cfg.predict_next_message_model_ref(), Some("p:predict"));
    assert_eq!(cfg.preflight_model_ref(), Some("p:preflight"));
    assert_eq!(
        cfg.harness_report_summarization_model_ref(),
        Some("p:harness")
    );

    cfg.auto_title = None;
    cfg.prompt_injection_guard.model = None;
    cfg.skill_injection = None;
    cfg.predict_next_message_model = None;
    cfg.preflight.model = None;
    cfg.harness_report_summarization = None;
    assert_eq!(cfg.auto_title_model_ref(), Some("p:utility"));
    assert_eq!(cfg.guard_model_ref(), Some("p:utility"));
    assert_eq!(cfg.skill_injection_model_ref(), Some("p:utility"));
    assert_eq!(cfg.predict_next_message_model_ref(), Some("p:utility"));
    assert_eq!(cfg.preflight_model_ref(), Some("p:utility"));
    assert_eq!(
        cfg.harness_report_summarization_model_ref(),
        Some("p:utility")
    );

    cfg.utility_model = None;
    assert_eq!(cfg.auto_title_model_ref(), None);
    assert_eq!(cfg.guard_model_ref(), None);
    assert_eq!(cfg.skill_injection_model_ref(), None);
    assert_eq!(cfg.predict_next_message_model_ref(), None);
    assert_eq!(cfg.preflight_model_ref(), None);
    assert_eq!(cfg.harness_report_summarization_model_ref(), None);
}

#[test]
fn compaction_model_inserts_utility_before_agent_fallback() {
    let mut cfg = ExtendedConfig {
        utility_model: Some("p:utility".into()),
        ..ExtendedConfig::default()
    };
    assert_eq!(cfg.compact_model_ref(), Some("p:utility"));
    cfg.compact_model = Some("p:compact".into());
    assert_eq!(cfg.compact_model_ref(), Some("p:compact"));
    cfg.compact_model = None;
    cfg.utility_model = None;
    assert_eq!(cfg.compact_model_ref(), None);
}

#[test]
fn translation_tier_falls_back_to_utility_model() {
    let mut cfg = ExtendedConfig {
        utility_model: Some("p:utility".into()),
        ..ExtendedConfig::default()
    };
    assert_eq!(cfg.translation_model_ref(), Some("p:utility"));
    cfg.translation_model = Some("p:translate".into());
    assert_eq!(cfg.translation_model_ref(), Some("p:translate"));
}

/// Cross-layer merge precedence is unchanged by the file consolidation:
/// the per-field layering (later/more-specific layer wins, omitted
/// fields inherit) still resolves from the same walk order — only the
/// on-disk filename the keys are read from changed to `config.json`.
#[test]
fn cross_layer_merge_precedence_unchanged_after_consolidation() {
    let tmp = TempDir::new().unwrap();
    // Two layers in walk order: global (less specific) then project.
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
    // Project (later) layer overrides only `threshold`...
    assert_eq!(resolved.threshold, InjectionThreshold::High);
    // ...and the omitted `check_prompt` inherits the global value.
    assert_eq!(resolved.check_prompt, "GLOBAL");
}

#[test]
fn preflight_config_defaults_off_with_default_prompt() {
    let cfg = ExtendedConfig::default();
    assert!(!cfg.preflight.enabled, "preflight is opt-in (default off)");
    assert!(cfg.preflight.model.is_none());
    assert!(cfg.preflight.preflight_prompt.is_none());
    // Model-ref falls back to the shared utility model.
    let mut cfg = cfg;
    cfg.utility_model = Some("p:m".into());
    assert_eq!(cfg.preflight_model_ref(), Some("p:m"));
    cfg.preflight.model = Some("o:mini".into());
    assert_eq!(
        cfg.preflight_model_ref(),
        Some("o:mini"),
        "the preflight override wins over the shared utility model"
    );
}

#[test]
fn compact_model_ref_falls_back_to_utility_then_agent_none() {
    // Unset → None (the driver maps None to the active agent's model).
    let mut cfg = ExtendedConfig::default();
    assert!(cfg.compact_model.is_none());
    assert_eq!(cfg.compact_model_ref(), None);

    // Set + non-empty → that model ref, verbatim.
    cfg.compact_model = Some("o:compact".into());
    assert_eq!(cfg.compact_model_ref(), Some("o:compact"));

    let mut cfg = ExtendedConfig {
        utility_model: Some("p:util".into()),
        ..ExtendedConfig::default()
    };
    assert_eq!(
        cfg.compact_model_ref(),
        Some("p:util"),
        "unset compact_model now borrows the utility model"
    );

    // Empty / whitespace-only is treated as unset (the "empty == unset"
    // edge case): resolves to utility_model, then active agent's model.
    cfg.compact_model = Some(String::new());
    assert_eq!(cfg.compact_model_ref(), Some("p:util"));
    cfg.compact_model = Some("   \t ".into());
    assert_eq!(cfg.compact_model_ref(), Some("p:util"));
}

#[test]
fn btw_model_ref_uses_only_explicit_non_empty_override() {
    let mut cfg = ExtendedConfig {
        utility_model: Some("p:utility".into()),
        ..ExtendedConfig::default()
    };
    assert_eq!(cfg.btw_model_ref(), None);

    cfg.btw_model = Some("o:btw".into());
    assert_eq!(cfg.btw_model_ref(), Some("o:btw"));

    cfg.btw_model = Some(String::new());
    assert_eq!(cfg.btw_model_ref(), None);
    cfg.btw_model = Some("   \t ".into());
    assert_eq!(cfg.btw_model_ref(), None);
}

#[test]
fn compact_model_and_prompt_round_trip_through_config_doc() {
    // The two new keys persist through the same `ExtendedConfigDoc`
    // round-trip the `/settings` save path uses.
    let cfg = ExtendedConfig {
        compact_model: Some("o:compact".into()),
        btw_model: Some("o:btw".into()),
        compact_prompt: Some("custom brief\nsecond line".into()),
        ..ExtendedConfig::default()
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ExtendedConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.compact_model.as_deref(), Some("o:compact"));
    assert_eq!(back.btw_model.as_deref(), Some("o:btw"));
    assert_eq!(
        back.compact_prompt.as_deref(),
        Some("custom brief\nsecond line")
    );

    // Unset keys are omitted from the serialized form (skip_serializing_if).
    let default_json = serde_json::to_string(&ExtendedConfig::default()).unwrap();
    assert!(!default_json.contains("compact_model"));
    assert!(!default_json.contains("btw_model"));
    assert!(!default_json.contains("compact_prompt"));
}

#[test]
fn preflight_cross_layer_merge_project_wins() {
    let tmp = TempDir::new().unwrap();
    // Global enables + sets a custom prompt; project flips `enabled` off
    // and omits the prompt (which must inherit the global one).
    let global = tmp.path().join("global-config.json");
    std::fs::write(
        &global,
        r#"{"preflight":{"enabled":true,"preflight_prompt":"GLOBAL PROMPT"}}"#,
    )
    .unwrap();
    let project = tmp.path().join("project-config.json");
    std::fs::write(&project, r#"{"preflight":{"enabled":false}}"#).unwrap();

    let resolved = resolve_preflight_from_paths(&[global, project]);
    assert!(!resolved.enabled, "project (later) layer overrides enabled");
    assert_eq!(
        resolved.preflight_prompt, "GLOBAL PROMPT",
        "omitted preflight_prompt inherits the global value"
    );
}

#[test]
fn preflight_config_round_trips_through_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.preflight.enabled = true;
    cfg.preflight.model = Some("openai:gpt-4o-mini".into());
    cfg.preflight.preflight_prompt = Some("CUSTOM".into());
    doc.write(&cfg).unwrap();

    let cfg2 = ExtendedConfigDoc::load(&path).unwrap().config();
    assert!(cfg2.preflight.enabled);
    assert_eq!(cfg2.preflight.model.as_deref(), Some("openai:gpt-4o-mini"));
    assert_eq!(cfg2.preflight.preflight_prompt.as_deref(), Some("CUSTOM"));
}

#[test]
fn vim_mode_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.tui.vim_mode = VimModeSetting::Enabled;
    cfg.tui.thinking = ThinkingDisplay::Verbose;
    cfg.name = Some("Christopher".into());
    cfg.packages_directory = Some(PathBuf::from("/tmp/pkgs"));
    doc.write(&cfg).unwrap();

    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let cfg2 = doc2.config();
    assert_eq!(cfg2.tui.vim_mode, VimModeSetting::Enabled);
    assert_eq!(cfg2.tui.thinking, ThinkingDisplay::Verbose);
    assert_eq!(cfg2.name.as_deref(), Some("Christopher"));
    assert_eq!(cfg2.packages_directory, Some(PathBuf::from("/tmp/pkgs")));
}

#[test]
fn unknown_root_keys_survive_write() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    let retired_key = ["trusted", "Only"].concat();
    let mut raw = serde_json::Map::new();
    raw.insert("future_feature".into(), serde_json::json!({"a": 1}));
    raw.insert(retired_key.clone(), serde_json::Value::Bool(true));
    std::fs::write(&path, serde_json::to_string(&raw).unwrap()).unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let cfg = doc.config();
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"future_feature\""));
    assert!(!on_disk.contains(&retired_key));
}

#[test]
fn partial_redact_and_tui_objects_parse_with_defaults_and_preserve_lists() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
                "redact": { "denylist": ["secret"], "allowlist": ["PUBLIC"] },
                "tui": { "show_cwd": true }
            }"#,
    )
    .unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    assert!(cfg.redact.enabled);
    assert_eq!(cfg.redact.denylist, vec!["secret".to_string()]);
    assert_eq!(cfg.redact.allowlist, vec!["PUBLIC".to_string()]);
    assert!(cfg.tui.show_cwd);
    assert!(cfg.tui.render_agent_markdown);
    cfg.name = Some("after-save".into());
    doc.write(&cfg).unwrap();
    let reloaded = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(reloaded.redact.denylist, vec!["secret".to_string()]);
    assert_eq!(reloaded.redact.allowlist, vec!["PUBLIC".to_string()]);
}

#[test]
fn project_writes_target_nearest_project_layer() {
    let tmp = TempDir::new().unwrap();
    let project = tmp.path().join("repo");
    let nested = project.join("nested");
    let parent_cfg = project.join(".cockpit/config.json");
    let nested_cfg = nested.join(".cockpit/config.json");
    std::fs::create_dir_all(parent_cfg.parent().unwrap()).unwrap();
    std::fs::create_dir_all(nested_cfg.parent().unwrap()).unwrap();
    std::fs::write(&parent_cfg, r#"{"name":"parent"}"#).unwrap();
    std::fs::write(&nested_cfg, r#"{"name":"nested"}"#).unwrap();
    let cwd = nested.join("src");
    std::fs::create_dir_all(&cwd).unwrap();

    let _trust = enter_trusted_workspace(&cwd);
    append_gitignore_allow_to_project(&cwd, "target/").unwrap();
    persist_review_default_participants(&cwd, vec!["scout".into()]).unwrap();

    let parent = std::fs::read_to_string(&parent_cfg).unwrap();
    let nested = std::fs::read_to_string(&nested_cfg).unwrap();
    assert!(
        !parent.contains("target/"),
        "parent layer changed: {parent}"
    );
    assert!(
        !parent.contains("default_participants"),
        "parent layer changed: {parent}"
    );
    assert!(
        nested.contains("target/"),
        "nested layer missing gitignore allow: {nested}"
    );
    assert!(
        nested.contains("default_participants"),
        "nested layer missing review participants: {nested}"
    );
}

#[test]
fn thinking_default_is_condensed() {
    assert_eq!(ThinkingDisplay::default(), ThinkingDisplay::Condensed);
}

#[test]
fn new_top_level_keys_have_expected_defaults() {
    let cfg = ExtendedConfig::default();
    assert!(cfg.utility_model.is_none());
    assert_eq!(
        cfg.prompt_injection_guard.threshold,
        InjectionThreshold::Off
    );
    assert!(cfg.prompt_injection_guard.check_prompt.is_none());
    assert!(cfg.prompt_injection_guard.model.is_none());
    assert_eq!(cfg.system_prompt.time_injection_interval_minutes, 5);
    assert!(cfg.tui.banner.enabled);
    // Redaction per-source defaults (§7): both sources on, default
    // env-file patterns are `.env` + `.env.local`.
    assert!(cfg.redact.scan_environment);
    assert!(cfg.redact.scan_dotenv);
    assert_eq!(cfg.redact.dotenv_patterns, vec![".env", ".env.local"]);
}

#[test]
fn redact_dotenv_patterns_round_trip_and_default_when_absent() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    // Absent `redact` block → the default patterns apply.
    std::fs::write(&path, "{}").unwrap();
    let absent = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(absent.redact.dotenv_patterns, vec![".env", ".env.local"]);

    // A custom pattern list round-trips through write/read.
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.redact.dotenv_patterns = vec![".env".into(), "secrets/*.env".into()];
    cfg.redact.scan_environment = false;
    doc.write(&cfg).unwrap();
    let reloaded = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(
        reloaded.redact.dotenv_patterns,
        vec![".env".to_string(), "secrets/*.env".to_string()]
    );
    assert!(!reloaded.redact.scan_environment);
}

#[test]
fn new_keys_round_trip_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.utility_model = Some("anthropic:claude-haiku-4-5".into());
    cfg.prompt_injection_guard.threshold = InjectionThreshold::Medium;
    cfg.prompt_injection_guard.model = Some("openai:gpt-4o-mini".into());
    cfg.system_prompt.time_injection_interval_minutes = 10;
    cfg.tui.banner.enabled = false;
    doc.write(&cfg).unwrap();

    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let cfg2 = doc2.config();
    assert_eq!(
        cfg2.utility_model.as_deref(),
        Some("anthropic:claude-haiku-4-5")
    );
    assert_eq!(
        cfg2.prompt_injection_guard.threshold,
        InjectionThreshold::Medium
    );
    assert_eq!(
        cfg2.prompt_injection_guard.model.as_deref(),
        Some("openai:gpt-4o-mini")
    );
    assert_eq!(cfg2.system_prompt.time_injection_interval_minutes, 10);
    assert!(!cfg2.tui.banner.enabled);
}

#[test]
fn clearing_utility_model_removes_the_key_from_disk() {
    // The /settings utility-model picker can clear the value back to
    // unset. Because `utility_model` is skip-if-none, the merge in
    // `write` won't overwrite a previously-stored value — the explicit
    // remove must drop it so the clear actually persists.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.utility_model = Some("anthropic:opus".into());
    doc.write(&cfg).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .contains("utility_model")
    );

    // Reload, clear, write — the key must be gone on disk and on reload.
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.utility_model = None;
    doc.write(&cfg).unwrap();
    assert!(
        !std::fs::read_to_string(&path)
            .unwrap()
            .contains("utility_model"),
        "cleared utility_model must not linger on disk"
    );
    let cfg2 = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(cfg2.utility_model, None);
}

#[test]
fn loop_guard_threshold_defaults_to_two() {
    let cfg = ExtendedConfig::default();
    assert_eq!(cfg.loop_guard.repeat_threshold, 2);
    assert_eq!(cfg.loop_guard.effective_threshold(), 2);
}

#[test]
fn loop_guard_threshold_clamps_below_two() {
    // A nonsensical threshold (< 2 would "fire on the first call
    // ever") is floored to 2 at read time.
    let cfg = LoopGuardConfig {
        repeat_threshold: 0,
    };
    assert_eq!(cfg.effective_threshold(), 2);
    let cfg = LoopGuardConfig {
        repeat_threshold: 1,
    };
    assert_eq!(cfg.effective_threshold(), 2);
    // A larger value is preserved.
    let cfg = LoopGuardConfig {
        repeat_threshold: 5,
    };
    assert_eq!(cfg.effective_threshold(), 5);
}

#[test]
fn loop_guard_threshold_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.loop_guard.repeat_threshold = 4;
    doc.write(&cfg).unwrap();
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    assert_eq!(doc2.config().loop_guard.repeat_threshold, 4);
}

#[test]
fn max_primary_rounds_defaults_to_unlimited_and_round_trips() {
    assert_eq!(ExtendedConfig::default().max_primary_rounds, 0);
    let parsed: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(parsed.max_primary_rounds, 0);

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.max_primary_rounds = 3;
    doc.write(&cfg).unwrap();

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"maxPrimaryRounds\""), "{on_disk}");
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    assert_eq!(doc2.config().max_primary_rounds, 3);
}

#[test]
fn caffeinate_display_awake_defaults_off_and_maps_to_system_only_scope() {
    let cfg = ExtendedConfig::default();
    assert!(
        !cfg.tui.caffeinate_display_awake,
        "default must keep the display free to sleep"
    );
    assert_eq!(cfg.tui.sleep_scope(), SleepScope::SystemOnly);
}

#[test]
fn caffeinate_display_awake_round_trips_and_maps_to_full_scope() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.tui.caffeinate_display_awake = true;
    doc.write(&cfg).unwrap();

    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let cfg2 = doc2.config();
    assert!(cfg2.tui.caffeinate_display_awake);
    assert_eq!(cfg2.tui.sleep_scope(), SleepScope::SystemAndDisplay);
}

#[test]
fn roster_trim_default_primary_is_build() {
    let cfg = ExtendedConfig::default();
    assert_eq!(cfg.default_primary_agent, DefaultPrimaryAgent::Build);
    assert_eq!(cfg.default_primary_agent.agent_name(), "Build");
    let parsed: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(parsed.default_primary_agent, DefaultPrimaryAgent::Build);
    assert_eq!(
        DefaultPrimaryAgent::Build.cycled(),
        DefaultPrimaryAgent::Plan
    );
    assert_eq!(
        DefaultPrimaryAgent::Plan.cycled(),
        DefaultPrimaryAgent::Build
    );
    assert_eq!(DefaultPrimaryAgent::Plan.agent_name(), "Plan");
}

#[test]
fn default_primary_agent_round_trips() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.default_primary_agent = DefaultPrimaryAgent::Plan;
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"defaultPrimaryAgent\""), "{on_disk}");
    assert!(on_disk.contains("plan"), "{on_disk}");
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    assert_eq!(
        doc2.config().default_primary_agent,
        DefaultPrimaryAgent::Plan
    );
}

#[test]
fn roster_trim_removed_default_primary_degrades_to_build() {
    for value in ["auto", "swarm", "unknown"] {
        let parsed: ExtendedConfig =
            serde_json::from_str(&format!(r#"{{"defaultPrimaryAgent":"{value}"}}"#)).unwrap();
        assert_eq!(
            parsed.default_primary_agent,
            DefaultPrimaryAgent::Build,
            "{value}"
        );

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, format!(r#"{{"defaultPrimaryAgent":"{value}"}}"#)).unwrap();
        let cfg = ExtendedConfigDoc::load(&path).unwrap().config();
        assert_eq!(cfg.default_primary_agent, DefaultPrimaryAgent::Build);
        assert_eq!(cfg.removed_default_primary_agent(), Some(value));
    }
}

#[test]
fn translation_defaults_empty_and_inactive() {
    let cfg = ExtendedConfig::default();
    assert!(cfg.translation.user_language.is_empty());
    assert!(cfg.translation.model_language.is_empty());
    assert!(!cfg.translation.is_active());
    // A config that omits the field reads the same inactive default.
    let parsed: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert!(!parsed.translation.is_active());
}

#[test]
fn translation_is_active_only_when_set_and_differing() {
    // Both set + differing → active.
    let cfg = TranslationConfig {
        user_language: "Spanish".into(),
        model_language: "English".into(),
    };
    assert!(cfg.is_active());

    // Equal languages (case/whitespace-insensitive) → inactive.
    let cfg = TranslationConfig {
        user_language: " English ".into(),
        model_language: "english".into(),
    };
    assert!(!cfg.is_active());

    // Either side empty → inactive (feature off / unconfigured).
    let cfg = TranslationConfig {
        user_language: "Spanish".into(),
        model_language: "   ".into(),
    };
    assert!(!cfg.is_active());
    let cfg = TranslationConfig {
        user_language: String::new(),
        model_language: "English".into(),
    };
    assert!(!cfg.is_active());
}

#[test]
fn translation_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.translation.user_language = "Spanish".into();
    cfg.translation.model_language = "English".into();
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"translation\""), "{on_disk}");
    assert!(on_disk.contains("Spanish"), "{on_disk}");
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let cfg2 = doc2.config();
    assert_eq!(cfg2.translation.user_language, "Spanish");
    assert_eq!(cfg2.translation.model_language, "English");
    assert!(cfg2.translation.is_active());
}

#[test]
fn llm_mode_defaults_to_defensive() {
    let cfg = ExtendedConfig::default();
    assert_eq!(cfg.llm_mode, LlmMode::Defensive);
    // A config that omits the field still reads the default.
    let parsed: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(parsed.llm_mode, LlmMode::Defensive);
}

#[test]
fn deepthink_defaults_disabled_and_parses_flag() {
    let cfg = ExtendedConfig::default();
    assert!(!cfg.deepthink.enabled);
    let parsed: ExtendedConfig = serde_json::from_str(r#"{"deepthink":{"enabled":true}}"#).unwrap();
    assert!(parsed.deepthink.enabled);
}

#[test]
fn llm_mode_parses_all_values() {
    let d: ExtendedConfig = serde_json::from_str(r#"{"llm_mode":"defensive"}"#).unwrap();
    assert_eq!(d.llm_mode, LlmMode::Defensive);
    let n: ExtendedConfig = serde_json::from_str(r#"{"llm_mode":"normal"}"#).unwrap();
    assert_eq!(n.llm_mode, LlmMode::Normal);
    let f: ExtendedConfig = serde_json::from_str(r#"{"llm_mode":"frontier"}"#).unwrap();
    assert_eq!(f.llm_mode, LlmMode::Frontier);
}

#[test]
fn llm_mode_unknown_value_is_rejected_with_backtick_and_valid_set() {
    let err = serde_json::from_str::<ExtendedConfig>(r#"{"llm_mode":"yolo"}"#)
        .expect_err("unknown llm_mode must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("`yolo`"),
        "offending value must be backticked: {msg}"
    );
    assert!(msg.contains("defensive"), "valid set must be listed: {msg}");
    assert!(msg.contains("normal"), "valid set must be listed: {msg}");
    assert!(msg.contains("frontier"), "valid set must be listed: {msg}");
}

#[test]
fn llm_mode_cycled_visits_all_modes() {
    assert_eq!(LlmMode::Defensive.cycled(), LlmMode::Normal);
    assert_eq!(LlmMode::Normal.cycled(), LlmMode::Frontier);
    assert_eq!(LlmMode::Frontier.cycled(), LlmMode::Defensive);
}

#[test]
fn llm_mode_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.llm_mode = LlmMode::Frontier;
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"llm_mode\""), "{on_disk}");
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    assert_eq!(doc2.config().llm_mode, LlmMode::Frontier);
}

#[test]
fn sandbox_escalation_defaults_enabled_and_round_trips() {
    assert!(ExtendedConfig::default().sandbox_escalation_enabled);
    let parsed: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert!(parsed.sandbox_escalation_enabled);

    let parsed: ExtendedConfig =
        serde_json::from_str(r#"{"sandboxEscalationEnabled":false}"#).unwrap();
    assert!(!parsed.sandbox_escalation_enabled);
    let parsed: ExtendedConfig =
        serde_json::from_str(r#"{"sandbox_escalation_enabled":false}"#).unwrap();
    assert!(!parsed.sandbox_escalation_enabled);

    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{"sandboxEscalationEnabled":true,"sandbox_escalation_enabled":false}"#,
    )
    .unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let cfg = doc.config();
    assert!(
        !cfg.sandbox_escalation_enabled,
        "legacy alias is still accepted on read"
    );
    doc.write(&cfg).unwrap();
    let raw: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        raw.get("sandbox_escalation_enabled"),
        Some(&Value::Bool(false))
    );
    assert!(raw.get("sandboxEscalationEnabled").is_none());
}

#[test]
fn approval_mode_defaults_to_manual_and_parses_all_values() {
    // Default + an omitted field both read `manual` (fail-safe default).
    assert_eq!(
        ExtendedConfig::default().default_approval_mode,
        ApprovalMode::Manual
    );
    let parsed: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(parsed.default_approval_mode, ApprovalMode::Manual);
    // All three spellings parse.
    for (json, expect) in [
        (r#"{"defaultApprovalMode":"manual"}"#, ApprovalMode::Manual),
        (r#"{"defaultApprovalMode":"auto"}"#, ApprovalMode::Auto),
        (r#"{"defaultApprovalMode":"yolo"}"#, ApprovalMode::Yolo),
    ] {
        let cfg: ExtendedConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.default_approval_mode, expect, "{json}");
    }
}

#[test]
fn approval_mode_cycles_manual_auto_yolo() {
    assert_eq!(ApprovalMode::Manual.cycled(), ApprovalMode::Auto);
    assert_eq!(ApprovalMode::Auto.cycled(), ApprovalMode::Yolo);
    assert_eq!(ApprovalMode::Yolo.cycled(), ApprovalMode::Manual);
}

#[test]
fn approval_policy_config_parses_risk_program_and_key_caps() {
    let cfg: ExtendedConfig = serde_json::from_str(
        r#"{
                "approvalPolicy": {
                    "riskMaxScope": { "destructive": "session" },
                    "programMaxScope": { "rm": "once" },
                    "keyMaxScope": { "gh pr": "project" }
                }
            }"#,
    )
    .unwrap();
    assert_eq!(
        cfg.approval_policy.risk_max_scope.get("destructive"),
        Some(&ApprovalPolicyScope::Session)
    );
    assert_eq!(
        cfg.approval_policy.program_max_scope.get("rm"),
        Some(&ApprovalPolicyScope::Once)
    );
    assert_eq!(
        cfg.approval_policy.key_max_scope.get("gh pr"),
        Some(&ApprovalPolicyScope::Project)
    );
}

#[test]
fn approval_policy_parses_dangerous_flags() {
    let cfg: ExtendedConfig = serde_json::from_str(
        r#"{
                "approvalPolicy": {
                    "dangerousFlags": {
                        "git push": {
                            "flags": ["--force", "--force-with-lease"],
                            "tier": "destructive"
                        },
                        "deploy": {
                            "flags": ["--profile=prod"],
                            "tier": "privileged"
                        }
                    }
                }
            }"#,
    )
    .unwrap();
    let git_push = cfg
        .approval_policy
        .dangerous_flags
        .get("git push")
        .expect("git push rule parsed");
    assert_eq!(git_push.flags, vec!["--force", "--force-with-lease"]);
    assert_eq!(git_push.tier, "destructive");

    let deploy = cfg
        .approval_policy
        .dangerous_flags
        .get("deploy")
        .expect("bare program rule parsed");
    assert_eq!(deploy.flags, vec!["--profile=prod"]);
    assert_eq!(deploy.tier, "privileged");
}

#[test]
fn approval_mode_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    // An unknown root key must survive the write (preserve-unknown).
    std::fs::write(&path, r#"{"futureKey": 1}"#).unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.default_approval_mode = ApprovalMode::Auto;
    doc.write(&cfg).unwrap();
    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(on_disk.contains("\"defaultApprovalMode\""), "{on_disk}");
    assert!(
        on_disk.contains("futureKey"),
        "unknown key dropped: {on_disk}"
    );
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    assert_eq!(doc2.config().default_approval_mode, ApprovalMode::Auto);
}

#[test]
fn skills_config_default_is_codex_mode_and_no_dirs() {
    let cfg = ExtendedConfig::default();
    assert!(
        cfg.skills.scan_dirs.is_empty(),
        "the struct default scans nothing; seeding is materialized only on a fresh install"
    );
    assert!(
        !cfg.skills.auto_bang_commands,
        "auto-`!` must default to disabled (Codex mode)"
    );
    assert!(
        !cfg.skills.ancestor_walk,
        "ancestor walk must default to off"
    );
}

#[test]
fn skills_absent_scan_dirs_parses_empty_not_seeded() {
    // An existing config that omits `scan_dirs` parses to an empty
    // list (clean break — no implicit re-seed at parse time).
    let cfg: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert!(cfg.skills.scan_dirs.is_empty());
    assert!(!cfg.skills.ancestor_walk);
}

#[test]
fn load_for_cwd_seeds_default_skill_scan_dirs_when_no_config_exists() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let cwd = tmp.path().join("project");
    std::fs::create_dir_all(cwd.join(".agents/skills/fresh-skill")).unwrap();
    std::fs::write(
        cwd.join(".agents/skills/fresh-skill/SKILL.md"),
        "---\nname: fresh-skill\ndescription: fresh default\n---\nBody",
    )
    .unwrap();

    let cfg = trusted_load_for_cwd(&cwd);
    assert_eq!(
        cfg.skills.scan_dirs,
        SEEDED_SCAN_DIRS
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn load_for_cwd_merges_home_and_project_with_project_scalar_winning() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let home_cfg = tmp.path().join("home/.config/cockpit/config.json");
    std::fs::create_dir_all(home_cfg.parent().unwrap()).unwrap();
    std::fs::write(
        &home_cfg,
        r#"{"name":"Home","tui":{"show_cwd":false},"skills":{"scan_dirs":["home-skills"]}}"#,
    )
    .unwrap();
    let project = tmp.path().join("repo");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    std::fs::write(
        project.join(".cockpit/config.json"),
        r#"{"name":"Project","skills":{"scan_dirs":["project-skills"]}}"#,
    )
    .unwrap();

    let cfg = trusted_load_for_cwd(&project);

    assert_eq!(cfg.name.as_deref(), Some("Project"));
    assert!(
        !cfg.tui.show_cwd,
        "omitted nested field inherits home layer"
    );
    assert_eq!(cfg.skills.scan_dirs, vec!["project-skills".to_string()]);
}

#[test]
fn load_for_cwd_keeps_valid_name_when_unrelated_known_field_is_malformed() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let cfg_path = tmp.path().join("home/.config/cockpit/config.json");
    std::fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
    std::fs::write(
        &cfg_path,
        r#"{
                "name": "Christopher",
                "tui": { "banner": { "enabled": true } },
                "schedule": "not an object"
            }"#,
    )
    .unwrap();
    let cwd = tmp.path().join("repo");
    std::fs::create_dir_all(&cwd).unwrap();

    let cfg = trusted_load_for_cwd(&cwd);

    assert_eq!(cfg.name.as_deref(), Some("Christopher"));
    assert!(cfg.tui.banner.enabled);
    assert_eq!(
        cfg.schedule.max_concurrent,
        default_max_concurrent_schedules()
    );
}

#[test]
fn load_for_cwd_legacy_jobs_cannot_override_canonical_schedule_or_drop_name() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let cfg_path = tmp.path().join("home/.config/cockpit/config.json");
    std::fs::create_dir_all(cfg_path.parent().unwrap()).unwrap();
    std::fs::write(
        &cfg_path,
        r#"{
                "name": "Christopher",
                "jobs": { "max_concurrent": 99 },
                "schedule": { "max_concurrent": 3 }
            }"#,
    )
    .unwrap();
    let cwd = tmp.path().join("repo");
    std::fs::create_dir_all(&cwd).unwrap();

    let cfg = trusted_load_for_cwd(&cwd);

    assert_eq!(cfg.name.as_deref(), Some("Christopher"));
    assert_eq!(cfg.schedule.max_concurrent, 3);
}

#[test]
fn load_for_cwd_more_specific_name_null_clears_broader_name() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let home_cfg = tmp.path().join("home/.config/cockpit/config.json");
    std::fs::create_dir_all(home_cfg.parent().unwrap()).unwrap();
    std::fs::write(&home_cfg, r#"{"name":"Home"}"#).unwrap();
    let project = tmp.path().join("repo");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    std::fs::write(project.join(".cockpit/config.json"), r#"{"name":null}"#).unwrap();

    let cfg = trusted_load_for_cwd(&project);

    assert_eq!(cfg.name, None);
}

#[test]
fn load_for_cwd_paths_merge_split_home_and_project_provider_models_by_id() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let home_cfg = tmp.path().join("home/.config/cockpit/config.json");
    std::fs::create_dir_all(home_cfg.parent().unwrap()).unwrap();
    std::fs::write(&home_cfg, "{}").unwrap();
    let home_provider =
        crate::config::providers::provider_file_path_for_config(&home_cfg, "p").unwrap();
    std::fs::create_dir_all(home_provider.parent().unwrap()).unwrap();
    std::fs::write(
        &home_provider,
        r#"{
                "url": "https://home.example/v1",
                "models": [
                    { "id": "m1", "name": "Model One" },
                    {
                        "id": "m2",
                        "name": "Model Two",
                        "favorite": true,
                        "timeout": { "ttft_secs": 80, "idle_secs": 40 }
                    },
                    { "id": "m3", "name": "Model Three" }
                ]
            }"#,
    )
    .unwrap();
    let project = tmp.path().join("repo");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    let project_cfg = project.join(".cockpit/config.json");
    std::fs::write(&project_cfg, "{}").unwrap();
    let project_provider =
        crate::config::providers::provider_file_path_for_config(&project_cfg, "p").unwrap();
    std::fs::create_dir_all(project_provider.parent().unwrap()).unwrap();
    std::fs::write(
        &project_provider,
        r#"{
                "models": [
                    { "id": "m2", "timeout": { "ttft_secs": 20, "idle_secs": 10 } }
                ]
            }"#,
    )
    .unwrap();

    let _trust = enter_trusted_workspace(&project);
    let cfg = crate::config::providers::ConfigDoc::load_effective(&project);

    let models = &cfg.providers.get("p").expect("provider survives").models;
    assert_eq!(
        models.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(),
        vec!["m1", "m2", "m3"]
    );
    let m2 = models.iter().find(|m| m.id == "m2").unwrap();
    assert_eq!(m2.name.as_deref(), Some("Model Two"));
    assert!(m2.favorite);
    let timeout = m2.timeout.as_ref().unwrap();
    assert_eq!(timeout.ttft_secs, 20);
    assert_eq!(timeout.idle_secs, 10);
}

#[test]
fn load_for_cwd_child_project_wins_over_parent_project() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let parent = tmp.path().join("repo");
    let child = parent.join("child");
    std::fs::create_dir_all(parent.join(".cockpit")).unwrap();
    std::fs::create_dir_all(child.join(".cockpit")).unwrap();
    std::fs::write(
        parent.join(".cockpit/config.json"),
        r#"{"name":"Parent","tui":{"show_branch":false}}"#,
    )
    .unwrap();
    std::fs::write(child.join(".cockpit/config.json"), r#"{"name":"Child"}"#).unwrap();

    let cfg = trusted_load_for_cwd(&child);

    assert_eq!(cfg.name.as_deref(), Some("Child"));
    assert!(
        !cfg.tui.show_branch,
        "child layer overrides name without dropping inherited parent tui field"
    );
}

#[test]
fn cockpit_config_env_overrides_normal_config_discovery() {
    let tmp = TempDir::new().unwrap();
    let env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let project = tmp.path().join("repo");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    std::fs::write(
        project.join(".cockpit/config.json"),
        r#"{"name":"Project"}"#,
    )
    .unwrap();
    let override_path = tmp.path().join("override.json");
    std::fs::write(&override_path, r#"{"name":"Override"}"#).unwrap();
    let _override = env.override_cockpit_config(&override_path);

    let cfg = trusted_load_for_cwd(&project);

    assert_eq!(cfg.name.as_deref(), Some("Override"));
}

#[test]
fn ancestor_walk_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.skills.ancestor_walk = true;
    doc.write(&cfg).unwrap();
    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    assert!(doc2.config().skills.ancestor_walk);
}

#[test]
fn skills_config_round_trips_through_extended_doc() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.skills.scan_dirs = vec!["~/.agents/skills".into(), "$PWD/.agents/skills".into()];
    cfg.skills.auto_bang_commands = true;
    doc.write(&cfg).unwrap();

    let doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let cfg2 = doc2.config();
    assert_eq!(
        cfg2.skills.scan_dirs,
        vec![
            "~/.agents/skills".to_string(),
            "$PWD/.agents/skills".to_string()
        ]
    );
    assert!(cfg2.skills.auto_bang_commands);
}

#[test]
fn config_resolution_reads_each_layer_once() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let project = tmp.path().join("repo");
    let child = project.join("child");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    std::fs::create_dir_all(child.join(".cockpit")).unwrap();
    std::fs::write(
        project.join(".cockpit/config.json"),
        r#"{"redact":{"denylist":["home-secret"]},"gitignore_allow":["home.log"]}"#,
    )
    .unwrap();
    std::fs::write(
        child.join(".cockpit/config.json"),
        r#"{"redact":{"allowlist":["project-ok"]},"gitignore_allow":["project.log"]}"#,
    )
    .unwrap();

    reset_config_layer_read_count();
    let cfg = trusted_load_for_cwd(&child);

    assert_eq!(config_layer_read_count(), 2);
    assert_eq!(cfg.redact.denylist, vec!["home-secret"]);
    assert_eq!(cfg.redact.allowlist, vec!["project-ok"]);
    assert_eq!(cfg.gitignore_allow, vec!["home.log", "project.log"]);
}

#[test]
fn config_resolution_result_unchanged_after_single_pass_rewrite() {
    let tmp = TempDir::new().unwrap();
    let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let project = tmp.path().join("repo");
    let child = project.join("child");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    std::fs::create_dir_all(child.join(".cockpit")).unwrap();
    std::fs::write(
        project.join(".cockpit/config.json"),
        r#"{
            "name":"Home",
            "redact":{"denylist":["shared-secret"],"extra_dotenv_paths":[".env.shared"]},
            "gitignore_allow":["home.log"],
            "llm_mode":"normal"
        }"#,
    )
    .unwrap();
    std::fs::write(
        child.join(".cockpit/config.json"),
        r#"{
            "name":"Project",
            "redact":{"denylist":["project-secret"],"allowlist":["safe"]},
            "gitignore_allow":["home.log","project.log"]
        }"#,
    )
    .unwrap();

    let cfg = trusted_load_for_cwd(&child);

    assert_eq!(cfg.name.as_deref(), Some("Project"));
    assert_eq!(
        cfg.redact.denylist,
        vec!["shared-secret".to_string(), "project-secret".to_string()]
    );
    assert_eq!(cfg.redact.allowlist, vec!["safe"]);
    assert_eq!(
        cfg.redact.extra_dotenv_paths,
        vec![PathBuf::from(".env.shared")]
    );
    assert_eq!(
        cfg.gitignore_allow,
        vec!["home.log".to_string(), "project.log".to_string()]
    );
    assert_eq!(cfg.llm_mode, LlmMode::Normal);
}

#[test]
fn web_custom_migrates_legacy_webfetch_tool_command() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
            "tools": {
                "webfetch": {
                    "enabled": false,
                    "command": "curl {url}",
                    "description": "Legacy fetch description"
                },
                "my_tool": {
                    "enabled": true,
                    "command": "echo {value}"
                }
            }
        }"#,
    )
    .unwrap();

    let cfg = ExtendedConfigDoc::load(&path).unwrap().config();

    assert_eq!(cfg.web.custom.fetch_command.as_deref(), Some("curl {url}"));
    assert!(!cfg.tools.contains_key("webfetch"));
    assert!(cfg.tools.contains_key("my_tool"));
}

#[test]
fn web_custom_migration_preserves_existing_typed_value() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
            "web": {
                "provider": "custom",
                "custom": {
                    "fetch_command": "existing {url}"
                }
            },
            "tools": {
                "webfetch": {
                    "enabled": true,
                    "command": "legacy {url}"
                }
            }
        }"#,
    )
    .unwrap();

    let cfg = ExtendedConfigDoc::load(&path).unwrap().config();

    assert_eq!(
        cfg.web.custom.fetch_command.as_deref(),
        Some("existing {url}")
    );
    assert!(!cfg.tools.contains_key("webfetch"));
}

#[test]
fn web_custom_migration_drops_legacy_descriptions() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
            "tools": {
                "webfetch": {
                    "enabled": true,
                    "command": "curl {url}",
                    "description": "do not preserve this"
                }
            }
        }"#,
    )
    .unwrap();

    let cfg = ExtendedConfigDoc::load(&path).unwrap().config();

    assert_eq!(cfg.web.custom.fetch_command.as_deref(), Some("curl {url}"));
    assert!(cfg.tools.values().all(|tool| {
        tool.description
            .as_deref()
            .is_none_or(|description| !description.contains("do not preserve this"))
    }));
}

#[test]
fn copy_on_release_defaults_true_when_omitted() {
    // Absent tui block.
    let empty: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert!(empty.tui.copy_on_release);

    // Present tui block, key omitted.
    let partial: ExtendedConfig =
        serde_json::from_str(r#"{"tui":{"mouse_capture":false}}"#).unwrap();
    assert!(partial.tui.copy_on_release);
    assert!(!partial.tui.mouse_capture);
}

#[test]
fn copy_on_release_struct_default_is_true() {
    assert!(TuiConfig::default().copy_on_release);
    assert!(ExtendedConfig::default().tui.copy_on_release);
}

#[test]
fn copy_on_release_false_round_trips() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.tui.copy_on_release = false;
    doc.write(&cfg).unwrap();

    let reloaded = ExtendedConfigDoc::load(&path).unwrap().config();
    assert!(!reloaded.tui.copy_on_release);

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("\"copy_on_release\": false")
            || on_disk.contains("\"copy_on_release\":false"),
        "{on_disk}"
    );

    // Explicit true after false round-trips as well.
    let mut doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg2 = doc2.config();
    cfg2.tui.copy_on_release = true;
    doc2.write(&cfg2).unwrap();
    assert!(
        ExtendedConfigDoc::load(&path)
            .unwrap()
            .config()
            .tui
            .copy_on_release
    );

    // Layering: project layer overrides home for tui.copy_on_release in both
    // directions (true→false and false→true).
    for (home_val, project_val) in [(true, false), (false, true)] {
        let layer_tmp = TempDir::new().unwrap();
        let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(layer_tmp.path());
        let home_cfg = layer_tmp.path().join("home/.config/cockpit/config.json");
        std::fs::create_dir_all(home_cfg.parent().unwrap()).unwrap();
        std::fs::write(
            &home_cfg,
            format!(r#"{{"tui":{{"copy_on_release":{home_val},"mouse_capture":true}}}}"#),
        )
        .unwrap();
        let project = layer_tmp.path().join("repo");
        std::fs::create_dir_all(project.join(".cockpit")).unwrap();
        std::fs::write(
            project.join(".cockpit/config.json"),
            format!(r#"{{"tui":{{"copy_on_release":{project_val}}}}}"#),
        )
        .unwrap();
        let layered = trusted_load_for_cwd(&project);
        assert_eq!(
            layered.tui.copy_on_release, project_val,
            "project layer must override home copy_on_release (home={home_val} project={project_val})"
        );
        assert!(
            layered.tui.mouse_capture,
            "omitted nested sibling inherits home layer"
        );
    }
}

#[test]
fn copy_on_release_omission_preserves_sibling_tui_values() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
            "tui": {
                "mouse_capture": false,
                "rich_text_copy": false,
                "hyperlinks": false,
                "show_cwd": false
            }
        }"#,
    )
    .unwrap();
    let cfg = ExtendedConfigDoc::load(&path).unwrap().config();
    assert!(cfg.tui.copy_on_release, "omitted key defaults true");
    assert!(!cfg.tui.mouse_capture);
    assert!(!cfg.tui.rich_text_copy);
    assert!(!cfg.tui.hyperlinks);
    assert!(!cfg.tui.show_cwd);
}

#[test]
fn clipboard_recovery_config_defaults_off_when_omitted() {
    // Absent tui block.
    let empty: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert_eq!(empty.tui.clipboard_recovery, ClipboardRecovery::Off);

    // Present tui block, key omitted; sibling still parses.
    let partial: ExtendedConfig =
        serde_json::from_str(r#"{"tui":{"mouse_capture":false}}"#).unwrap();
    assert_eq!(partial.tui.clipboard_recovery, ClipboardRecovery::Off);
    assert!(!partial.tui.mouse_capture);
}

#[test]
fn clipboard_recovery_config_struct_default_is_off() {
    assert_eq!(
        TuiConfig::default().clipboard_recovery,
        ClipboardRecovery::Off
    );
    assert_eq!(
        ExtendedConfig::default().tui.clipboard_recovery,
        ClipboardRecovery::Off
    );
}

#[test]
fn clipboard_recovery_config_parses_private_file() {
    let cfg: ExtendedConfig =
        serde_json::from_str(r#"{"tui":{"clipboard_recovery":"private-file"}}"#).unwrap();
    assert_eq!(cfg.tui.clipboard_recovery, ClipboardRecovery::PrivateFile);
}

#[test]
fn clipboard_recovery_config_rejects_invalid_values() {
    for bad in [
        r#"{"tui":{"clipboard_recovery":"on"}}"#,
        r#"{"tui":{"clipboard_recovery":"private_file"}}"#,
        r#"{"tui":{"clipboard_recovery":true}}"#,
        r#"{"tui":{"clipboard_recovery":1}}"#,
        r#"{"tui":{"clipboard_recovery":null}}"#,
    ] {
        assert!(
            serde_json::from_str::<ExtendedConfig>(bad).is_err(),
            "expected {bad} to be rejected"
        );
    }
}

#[test]
fn clipboard_recovery_config_round_trips() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    let mut doc = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg = doc.config();
    cfg.tui.clipboard_recovery = ClipboardRecovery::PrivateFile;
    doc.write(&cfg).unwrap();

    let reloaded = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(
        reloaded.tui.clipboard_recovery,
        ClipboardRecovery::PrivateFile
    );

    let on_disk = std::fs::read_to_string(&path).unwrap();
    assert!(
        on_disk.contains("\"clipboard_recovery\": \"private-file\"")
            || on_disk.contains("\"clipboard_recovery\":\"private-file\""),
        "{on_disk}"
    );

    // Explicit off after private-file round-trips as well.
    let mut doc2 = ExtendedConfigDoc::load(&path).unwrap();
    let mut cfg2 = doc2.config();
    cfg2.tui.clipboard_recovery = ClipboardRecovery::Off;
    doc2.write(&cfg2).unwrap();
    assert_eq!(
        ExtendedConfigDoc::load(&path)
            .unwrap()
            .config()
            .tui
            .clipboard_recovery,
        ClipboardRecovery::Off
    );

    // Layering: project layer overrides home in both directions, and an
    // omitted sibling still inherits the home layer (no environment
    // override/kill switch exists — persisted layered config is the sole
    // setting).
    for (home_val, project_val) in [
        (ClipboardRecovery::Off, ClipboardRecovery::PrivateFile),
        (ClipboardRecovery::PrivateFile, ClipboardRecovery::Off),
    ] {
        let layer_tmp = TempDir::new().unwrap();
        let _env = crate::config::dirs::test_support::IsolatedCockpitHome::new(layer_tmp.path());
        let home_cfg = layer_tmp.path().join("home/.config/cockpit/config.json");
        std::fs::create_dir_all(home_cfg.parent().unwrap()).unwrap();
        std::fs::write(
            &home_cfg,
            format!(
                r#"{{"tui":{{"clipboard_recovery":{:?},"mouse_capture":true}}}}"#,
                serde_kebab(home_val)
            ),
        )
        .unwrap();
        let project = layer_tmp.path().join("repo");
        std::fs::create_dir_all(project.join(".cockpit")).unwrap();
        std::fs::write(
            project.join(".cockpit/config.json"),
            format!(
                r#"{{"tui":{{"clipboard_recovery":{:?}}}}}"#,
                serde_kebab(project_val)
            ),
        )
        .unwrap();
        let layered = trusted_load_for_cwd(&project);
        assert_eq!(
            layered.tui.clipboard_recovery, project_val,
            "project layer must override home clipboard_recovery (home={home_val:?} project={project_val:?})"
        );
        assert!(
            layered.tui.mouse_capture,
            "omitted nested sibling inherits home layer"
        );
    }
}

fn serde_kebab(value: ClipboardRecovery) -> &'static str {
    match value {
        ClipboardRecovery::Off => "off",
        ClipboardRecovery::PrivateFile => "private-file",
    }
}

#[test]
fn clipboard_recovery_config_omission_preserves_sibling_tui_values() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{
            "tui": {
                "mouse_capture": false,
                "rich_text_copy": false,
                "hyperlinks": false,
                "show_cwd": false
            }
        }"#,
    )
    .unwrap();
    let cfg = ExtendedConfigDoc::load(&path).unwrap().config();
    assert_eq!(
        cfg.tui.clipboard_recovery,
        ClipboardRecovery::Off,
        "omitted key defaults off"
    );
    assert!(!cfg.tui.mouse_capture);
    assert!(!cfg.tui.rich_text_copy);
    assert!(!cfg.tui.hyperlinks);
    assert!(!cfg.tui.show_cwd);
}

mod guards_and_resolvers;

#[test]
fn response_metrics_tokenizer_config_defaults_and_round_trips() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(&path, "{}").unwrap();
    assert_eq!(
        ExtendedConfigDoc::load(&path)
            .unwrap()
            .config()
            .response_metrics_tokenizer,
        cockpit_tokenizer::TiktokenEncoding::Cl100k
    );
    std::fs::write(&path, r#"{"response_metrics_tokenizer":"o200k_base"}"#).unwrap();
    assert_eq!(
        ExtendedConfigDoc::load(&path)
            .unwrap()
            .config()
            .response_metrics_tokenizer,
        cockpit_tokenizer::TiktokenEncoding::O200k
    );
    assert!(serde_json::from_str::<cockpit_tokenizer::TiktokenEncoding>("\"unknown\"").is_err());
}

#[test]
fn settings_advisory_load_remains_editable_with_invalid_response_metrics_tokenizer() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("config.json");
    std::fs::write(
        &path,
        r#"{"name":"editable","response_metrics_tokenizer":"invalid"}"#,
    )
    .unwrap();
    let (config, warnings) = ExtendedConfigDoc::load(&path)
        .unwrap()
        .config_with_warnings();
    assert_eq!(config.name.as_deref(), Some("editable"));
    assert_eq!(
        config.response_metrics_tokenizer,
        cockpit_tokenizer::TiktokenEncoding::Cl100k
    );
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("response_metrics_tokenizer"))
    );
}

#[test]
fn daemon_effective_load_rejects_invalid_response_metrics_tokenizer() {
    let tmp = TempDir::new().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let project = tmp.path().join("repo");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    std::fs::write(
        project.join(".cockpit/config.json"),
        r#"{"response_metrics_tokenizer":"invalid"}"#,
    )
    .unwrap();
    let _trust = enter_trusted_workspace(&project);
    assert!(
        load_for_cwd_for_daemon_contract(&project)
            .response_metrics_tokenizer_validation
            .is_err()
    );
}

#[test]
fn invalid_response_metrics_tokenizer_fails_effective_load() {
    let tmp = TempDir::new().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let project = tmp.path().join("repo");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    std::fs::write(
        project.join(".cockpit/config.json"),
        r#"{"response_metrics_tokenizer":"not-an-encoding"}"#,
    )
    .unwrap();
    let _trust = enter_trusted_workspace(&project);
    let load = load_for_cwd_for_daemon_contract(&project);
    assert_eq!(load.participating_layers.len(), 1);
    assert!(load.response_metrics_tokenizer_validation.is_err());
}

#[test]
fn response_metrics_tokenizer_daemon_load_respects_layered_trust_policy() {
    let tmp = TempDir::new().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let global = tmp.path().join("home/.config/cockpit/config.json");
    std::fs::create_dir_all(global.parent().unwrap()).unwrap();
    std::fs::write(
        &global,
        r#"{"response_metrics_tokenizer":"invalid-global"}"#,
    )
    .unwrap();
    let project = tmp.path().join("repo");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    std::fs::write(
        project.join(".cockpit/config.json"),
        r#"{"response_metrics_tokenizer":"o200k_base"}"#,
    )
    .unwrap();
    {
        let _trust = enter_trusted_workspace(&project);
        let load = load_for_cwd_for_daemon_contract(&project);
        assert!(load.response_metrics_tokenizer_validation.is_err());
        assert_eq!(load.participating_layers.len(), 2);
    }

    std::fs::write(&global, "{}").unwrap();
    std::fs::write(
        project.join(".cockpit/config.json"),
        r#"{"response_metrics_tokenizer":"invalid-project"}"#,
    )
    .unwrap();
    let _ignore_config = crate::config::trust::enter_workspace_trust_policy(
        crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(&project).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        },
    );
    let load = load_for_cwd_for_daemon_contract(&project);
    assert!(load.response_metrics_tokenizer_validation.is_ok());
    assert_eq!(load.participating_layers, vec![global]);
}

#[test]
fn daemon_tokenizer_validation_keeps_whole_document_failures_advisory() {
    let tmp = TempDir::new().unwrap();
    let _home = crate::config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let project = tmp.path().join("repo");
    std::fs::create_dir_all(project.join(".cockpit")).unwrap();
    let path = project.join(".cockpit/config.json");
    let _trust = enter_trusted_workspace(&project);
    for contents in ["not json", "[]"] {
        std::fs::write(&path, contents).unwrap();
        let load = load_for_cwd_for_daemon_contract(&project);
        assert!(load.response_metrics_tokenizer_validation.is_ok());
        assert_eq!(
            load.config.response_metrics_tokenizer,
            cockpit_tokenizer::TiktokenEncoding::Cl100k
        );
    }
}
