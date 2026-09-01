use super::*;
use tempfile::TempDir;

fn source(path: PathBuf, kind: ConfigDirKind) -> HookConfigSource {
    HookConfigSource {
        kind: HookSourceKind::Layer(kind),
        path,
    }
}

fn write_config(path: &Path, value: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, value).unwrap();
}

#[test]
fn hooks_config_parses_and_preserves_source() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("project/.cockpit/config.json");
    write_config(
        &path,
        r#"{"hooks":{"preToolUse":[{"matcher":["mcp","bash"],"command":["./hooks/check-tool","--strict"],"timeoutSecs":7,"env":{"LOG_LEVEL":"info"}}],"stop":[{"command":["verify"]}]}}"#,
    );

    let registry = resolve_hooks_from_sources(&[source(path.clone(), ConfigDirKind::Project)]);
    assert!(registry.warnings.is_empty());
    assert_eq!(registry.hooks.len(), 2);
    let pre = &registry.hooks[0];
    assert_eq!(pre.event, HookEvent::PreToolUse);
    assert_eq!(
        pre.matcher,
        Some(BTreeSet::from(["bash".into(), "mcp".into()]))
    );
    assert_eq!(
        pre.command[0],
        temp.path()
            .join("project/.cockpit/hooks/check-tool")
            .to_string_lossy()
    );
    assert_eq!(&pre.command[1], "--strict");
    assert_eq!(pre.timeout_secs, 7);
    assert_eq!(pre.env.get("LOG_LEVEL").map(String::as_str), Some("info"));
    assert_eq!(pre.source_config_path, path);
    assert_eq!(pre.source_directory, temp.path().join("project/.cockpit"));
    let stop = &registry.hooks[1];
    assert_eq!(stop.event, HookEvent::Stop);
    assert_eq!(stop.matcher, None);
    assert_eq!(stop.timeout_secs, 60);
    assert_eq!(stop.command, ["verify"]);
}

#[test]
fn modes_session_setup_captured_project_hook_bytes_never_reopen_swapped_source_path() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("workspace/.cockpit/config.json");
    let retained_bytes = br#"{"hooks":{"sessionStart":[{"command":["retained-hook"]}]}}"#;
    write_config(
        &path,
        r#"{"hooks":{"sessionStart":[{"command":["attacker-hook"]}]}}"#,
    );

    // The source label is intentionally the mutable pathname that now names
    // an attacker replacement. The parser must consume the bytes acquired by
    // the retained workspace capability, not reopen that pathname.
    let registry = resolve_hooks_from_captured_sources(&[(
        source(path, ConfigDirKind::Project),
        Ok(Some(retained_bytes.to_vec())),
    )]);

    assert!(registry.warnings.is_empty());
    assert_eq!(registry.hooks.len(), 1);
    assert_eq!(registry.hooks[0].command, ["retained-hook"]);
    assert_ne!(registry.hooks[0].command, ["attacker-hook"]);
}

#[test]
fn modes_session_setup_captured_relative_project_hook_requires_retained_authority() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("workspace/.cockpit/config.json");
    let registry = resolve_hooks_from_captured_sources(&[(
        source(path, ConfigDirKind::Project),
        Ok(Some(
            br#"{"hooks":{"sessionStart":[{"command":["./hooks/check"]}]}}"#.to_vec(),
        )),
    )]);

    assert!(registry.warnings.is_empty());
    assert_eq!(registry.hooks.len(), 1);
    let hook = &registry.hooks[0];
    assert_eq!(hook.command, ["hooks/check"]);
    assert!(matches!(
        &hook.execution,
        HookExecutionProvenance::RetainedRelative { .. }
    ));
    assert!(
        hook.retained_execution_launch().is_err(),
        "the parser must not silently reopen the source-relative pathname"
    );
}

#[test]
fn hooks_config_event_table_and_defaults() {
    assert_eq!(
        HookEvent::ALL.map(HookEvent::key),
        [
            "sessionStart",
            "userPromptSubmit",
            "preToolUse",
            "postToolUse",
            "postToolUseFailure",
            "permissionDenied",
            "stop",
            "stopFailure",
            "subagentStart",
            "subagentStop",
            "preCompact",
            "postCompact",
            "sessionEnd",
        ]
    );
    assert_eq!(HookEvent::ALL.len(), 13);
    let expected = [
        (
            HookEvent::SessionStart,
            HookGate::Observe,
            HookApplicability::RootAndChild,
            HookMatcherPolicy::Closed(&["fresh", "resume"]),
            5,
        ),
        (
            HookEvent::UserPromptSubmit,
            HookGate::Observe,
            HookApplicability::RootOnly,
            HookMatcherPolicy::Closed(&["user", "queued"]),
            5,
        ),
        (
            HookEvent::PreToolUse,
            HookGate::Tool,
            HookApplicability::OrdinaryToolOnly,
            HookMatcherPolicy::CanonicalToolName,
            5,
        ),
        (
            HookEvent::PostToolUse,
            HookGate::Observe,
            HookApplicability::RealOrdinaryExecutionOnly,
            HookMatcherPolicy::CanonicalToolName,
            5,
        ),
        (
            HookEvent::PostToolUseFailure,
            HookGate::Observe,
            HookApplicability::RealOrdinaryExecutionOnly,
            HookMatcherPolicy::CanonicalToolName,
            5,
        ),
        (
            HookEvent::PermissionDenied,
            HookGate::Observe,
            HookApplicability::AnyDeniedToolApproval,
            HookMatcherPolicy::CanonicalToolName,
            5,
        ),
        (
            HookEvent::Stop,
            HookGate::Stop,
            HookApplicability::NormalRootDoneOnly,
            HookMatcherPolicy::Closed(&["end_turn"]),
            60,
        ),
        (
            HookEvent::StopFailure,
            HookGate::Observe,
            HookApplicability::InferenceErrorOnly,
            HookMatcherPolicy::ErrorClass,
            5,
        ),
        (
            HookEvent::SubagentStart,
            HookGate::Observe,
            HookApplicability::ChildOnly,
            HookMatcherPolicy::ChildAgentType,
            5,
        ),
        (
            HookEvent::SubagentStop,
            HookGate::Stop,
            HookApplicability::ChildOnly,
            HookMatcherPolicy::ChildAgentType,
            60,
        ),
        (
            HookEvent::PreCompact,
            HookGate::Observe,
            HookApplicability::SuccessfulCompactionOnly,
            HookMatcherPolicy::Closed(&["manual", "auto"]),
            5,
        ),
        (
            HookEvent::PostCompact,
            HookGate::Observe,
            HookApplicability::SuccessfulCompactionOnly,
            HookMatcherPolicy::Closed(&["manual", "auto"]),
            5,
        ),
        (
            HookEvent::SessionEnd,
            HookGate::Observe,
            HookApplicability::EverySession,
            HookMatcherPolicy::Closed(&[
                "completed",
                "interrupted",
                "cancelled",
                "shutdown",
                "error",
            ]),
            5,
        ),
    ];
    for (event, gate, applicability, matcher, timeout) in expected {
        let policy = event.policy();
        assert_eq!(
            (
                policy.gate,
                policy.applicability,
                policy.default_timeout_secs
            ),
            (gate, applicability, timeout)
        );
        assert_eq!(policy.matcher, matcher);
    }
}

#[test]
fn hooks_config_origin_index_follows_document_handler_order() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("config.json");
    write_config(
        &path,
        r#"{"hooks":{"stop":[{"command":["first"]}],"Unsupported":[{"command":["foreign"]}],"sessionStart":[{"command":["third"]}]}}"#,
    );
    let registry = resolve_hooks_from_sources(&[source(path, ConfigDirKind::Project)]);
    assert!(registry.hooks[0].origin.as_str().ends_with(":0"));
    assert!(registry.hooks[1].origin.as_str().ends_with(":2"));
}

#[test]
fn hooks_config_layers_additively_and_first_wins() {
    let temp = TempDir::new().unwrap();
    let global = temp.path().join("global/config.json");
    let project = temp.path().join("project/config.json");
    write_config(
        &global,
        r#"{"hooks":{"preToolUse":[{"matcher":["bash"],"command":["bash","-n"],"timeoutSecs":2,"env":{"WINNER":"yes"}},{"command":["global-only"]}]}}"#,
    );
    write_config(
        &project,
        r#"{"hooks":{"preToolUse":[{"matcher":["bash"],"command":["bash","-n"],"timeoutSecs":99,"env":{"LOSER":"yes"}},{"command":["project-only"]}]}}"#,
    );
    let registry = resolve_hooks_from_sources(&[
        source(global, ConfigDirKind::HomeXdg),
        source(project, ConfigDirKind::Project),
    ]);
    assert_eq!(registry.hooks.len(), 3);
    assert_eq!(
        registry
            .hooks
            .iter()
            .map(|hook| hook.command[0].as_str())
            .collect::<Vec<_>>(),
        ["bash", "global-only", "project-only"]
    );
    assert_eq!(registry.hooks[0].timeout_secs, 2);
    assert!(registry.hooks[0].env.contains_key("WINNER"));
    assert!(registry.hooks[0].origin.as_str().starts_with("global:"));
}

#[test]
fn hooks_config_origin_is_nonpath_and_stable() {
    let temp = TempDir::new().unwrap();
    let cases = [
        (ConfigDirKind::HomeXdg, "global"),
        (ConfigDirKind::MachineLocal, "machine"),
        (ConfigDirKind::Project, "project"),
    ];
    let mut sources = Vec::new();
    for (position, (kind, _)) in cases.iter().enumerate() {
        let path = temp.path().join(format!("source-{position}/config.json"));
        write_config(
            &path,
            &format!(r#"{{"hooks":{{"preToolUse":[{{"command":["command-{position}"]}}]}}}}"#),
        );
        sources.push(source(path, kind.clone()));
    }
    let explicit_path = temp.path().join("explicit/config.json");
    write_config(
        &explicit_path,
        r#"{"hooks":{"preToolUse":[{"command":["explicit-command"]}]}}"#,
    );
    sources.push(HookConfigSource {
        kind: HookSourceKind::Explicit,
        path: explicit_path,
    });

    let first = resolve_hooks_from_sources(&sources);
    let second = resolve_hooks_from_sources(&sources);
    assert_eq!(first.hooks, second.hooks);
    for (hook, expected_kind) in first
        .hooks
        .iter()
        .zip(["global", "user", "machine", "project", "explicit"])
    {
        let expected = format!(
            "{expected_kind}:{}:0",
            source_digest(&hook.source_config_path)
        );
        assert_eq!(hook.origin.as_str(), expected);
        let digest = hook.origin.as_str().split(':').nth(1).unwrap();
        assert_eq!(digest.len(), 16);
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert!(
            !hook
                .origin
                .as_str()
                .contains(temp.path().to_string_lossy().as_ref())
        );
    }

    let ancestor = temp.path().join("ancestor/.cockpit/config.json");
    let child = temp.path().join("ancestor/child/.cockpit/config.json");
    write_config(
        &ancestor,
        r#"{"hooks":{"preToolUse":[{"command":["same-position-a"]}]}}"#,
    );
    write_config(
        &child,
        r#"{"hooks":{"preToolUse":[{"command":["same-position-b"]}]}}"#,
    );
    let projects = resolve_hooks_from_sources(&[
        source(ancestor, ConfigDirKind::Project),
        source(child, ConfigDirKind::Project),
    ]);
    assert_ne!(projects.hooks[0].origin, projects.hooks[1].origin);

    let audit = serde_json::json!({
        "event": projects.hooks[0].event.key(),
        "hook": projects.hooks[0].origin.as_str(),
        "origin": projects.hooks[0].origin.as_str(),
        "status": "success",
        "duration_ms": 0
    });
    cockpit_db::db::session_log::HookRunAudit::from_json(&audit).unwrap();
}

#[test]
fn hooks_config_explicit_override_uses_explicit_origin() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("explicit.json");
    write_config(
        &path,
        r#"{"hooks":{"preToolUse":[{"command":["explicit"]}]}}"#,
    );
    let _override = crate::config::dirs::test_support::CockpitConfigOverride::new(&path);
    let registry = resolve_hooks_for_cwd(temp.path());
    assert_eq!(registry.hooks.len(), 1);
    assert!(registry.hooks[0].origin.as_str().starts_with("explicit:"));
    assert_eq!(registry.hooks[0].source_config_path, path);
}

#[test]
fn hooks_config_trust_excludes_project_layer() {
    use crate::config::trust::{
        WorkspaceTrustPolicy, enter_workspace_trust_policy, resolve_trust_root,
    };
    use crate::db::workspace_trust::WorkspaceTrustMode;

    if std::env::var_os(COCKPIT_CONFIG_ENV).is_some() {
        return;
    }
    let temp = TempDir::new().unwrap();
    std::fs::create_dir(temp.path().join(".git")).unwrap();
    let path = temp.path().join(".cockpit/config.json");
    write_config(
        &path,
        r#"{"hooks":{"preToolUse":[{"command":["project-trust-marker"]}]}}"#,
    );
    let root = resolve_trust_root(temp.path()).unwrap();
    let has_project_hook = || {
        resolve_hooks_for_cwd(temp.path()).hooks.iter().any(|hook| {
            hook.command
                .first()
                .is_some_and(|argv0| argv0 == "project-trust-marker")
        })
    };

    assert!(
        !has_project_hook(),
        "unset trust must exclude project config"
    );
    for mode in [
        WorkspaceTrustMode::IgnoreConfig,
        WorkspaceTrustMode::Untrusted,
    ] {
        let _guard = enter_workspace_trust_policy(WorkspaceTrustPolicy {
            root: root.clone(),
            mode,
        });
        assert!(!has_project_hook());
    }
    let _guard = enter_workspace_trust_policy(WorkspaceTrustPolicy {
        root,
        mode: WorkspaceTrustMode::Trust,
    });
    assert!(has_project_hook());
}

#[test]
fn hooks_config_resolves_relative_command_from_declaring_layer() {
    let temp = TempDir::new().unwrap();
    let global = temp.path().join("global/config.json");
    let project = temp.path().join("project/config.json");
    let json = r#"{"hooks":{"preToolUse":[{"command":["./bin/check"]}]}}"#;
    write_config(&global, json);
    write_config(&project, json);
    let registry = resolve_hooks_from_sources(&[
        source(global, ConfigDirKind::HomeXdg),
        source(project, ConfigDirKind::Project),
    ]);
    assert_eq!(registry.hooks.len(), 2);
    assert_eq!(
        registry.hooks[0].command[0],
        temp.path().join("global/bin/check").to_string_lossy()
    );
    assert_eq!(
        registry.hooks[1].command[0],
        temp.path().join("project/bin/check").to_string_lossy()
    );
}

#[test]
fn hooks_config_invalid_handlers_are_local_and_warned() {
    let temp = TempDir::new().unwrap();
    let first = temp.path().join("first/config.json");
    let later = temp.path().join("later/config.json");
    write_config(
        &first,
        r#"{"hooks":{"PreToolUse":[{"command":["vendor"]}],"stop":[{"command":"shell text"},{"matcher":[],"command":["empty-matcher"]},{"matcher":["wrong"],"command":["bad-matcher"]},{"command":[]},{"command":["","empty-item"]},{"command":["timeout-zero"],"timeoutSecs":0},{"command":["timeout-high"],"timeoutSecs":601},{"command":["empty-env-key"],"env":{"":"value"}},{"command":["https://example.test/hook"]},{"command":["valid"]},{"command":["secret","do-not-log"],"env":{"TOKEN":1}}]}}"#,
    );
    write_config(&later, r#"{"hooks":{"stop":[{"command":["later"]}]}}"#);
    let registry = resolve_hooks_from_sources(&[
        source(first, ConfigDirKind::HomeXdg),
        source(later, ConfigDirKind::Project),
    ]);
    assert_eq!(
        registry
            .hooks
            .iter()
            .map(|hook| hook.command[0].as_str())
            .collect::<Vec<_>>(),
        ["valid", "later"]
    );
    assert!(registry.warnings.len() >= 10);
    let warnings = registry
        .warnings
        .iter()
        .map(|warning| warning.message.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!warnings.contains("do-not-log"));
    assert!(!warnings.contains("TOKEN"));
}

#[test]
fn hooks_config_rejects_non_native_formats() {
    let temp = TempDir::new().unwrap();
    let toml = temp.path().join("toml/config.json");
    let foreign = temp.path().join("foreign/config.json");
    write_config(&toml, "[hooks]\npreToolUse = []\n");
    write_config(
        &foreign,
        r#"{"hooks":{"PreToolUse":[{"command":["claude"]}],"beforeShellExecution":[{"command":["cursor"]}],"preToolUse":[{"matcher":".*","command":["regex"]},{"matcher":["Bash|Edit"],"command":["regex-array"]},{"matcher":["Bash*"],"command":["glob-array"]},{"type":"http","command":["local"]},{"plugin":"x","command":["plugin"]},{"agent":"x","command":["agent"]}],"subagentStart":[{"matcher":["child.*"],"command":["child-regex"]}],"stopFailure":[{"matcher":["network|timeout"],"command":["error-regex"]}]}}"#,
    );
    let registry = resolve_hooks_from_sources(&[
        source(toml, ConfigDirKind::HomeXdg),
        source(foreign, ConfigDirKind::Project),
    ]);
    assert!(registry.hooks.is_empty());
    assert!(registry.warnings.len() >= 10);
}

#[test]
fn hooks_config_error_class_matcher_is_a_closed_vocabulary() {
    // `stopFailure` matches on an exact inference-error-class token (runtime
    // matching is set membership, never regex). A matcher naming a recognized
    // class resolves; the values are preserved verbatim.
    let temp = TempDir::new().unwrap();
    let ok = temp.path().join("ok/.cockpit/config.json");
    write_config(
        &ok,
        r#"{"hooks":{"stopFailure":[{"matcher":["network","provider_rate_limit"],"command":["notify"]}]}}"#,
    );
    let registry = resolve_hooks_from_sources(&[source(ok, ConfigDirKind::Project)]);
    assert!(registry.warnings.is_empty());
    assert_eq!(registry.hooks.len(), 1);
    assert_eq!(registry.hooks[0].event, HookEvent::StopFailure);
    assert_eq!(
        registry.hooks[0].matcher,
        Some(BTreeSet::from([
            "network".into(),
            "provider_rate_limit".into(),
        ]))
    );

    // A token outside the closed vocabulary is rejected (and warned), not
    // admitted as a dead hook that could never fire.
    let bad = temp.path().join("bad/.cockpit/config.json");
    write_config(
        &bad,
        r#"{"hooks":{"stopFailure":[{"matcher":["not_a_real_class"],"command":["notify"]}]}}"#,
    );
    let rejected = resolve_hooks_from_sources(&[source(bad, ConfigDirKind::Project)]);
    assert!(rejected.hooks.is_empty());
    assert!(!rejected.warnings.is_empty());
}
