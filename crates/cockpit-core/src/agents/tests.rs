//! Tests for agent definition parsing, override resolution, invariant
//! validation, eject/reset, and name→path resolution.

use std::fs;
use std::path::Path;

use super::invariants::{LOCK_WRITE_TOOLS, SANDBOX_ONLY_TOOLS};
use super::*;

#[test]
fn agent_profile_resolution_owned_path_uses_the_source_specific_loader() {
    use cockpit_db::db::agent_installations::{
        AgentInstallationRow, AgentInstallationScope, AgentObservationRow,
    };

    fn installation(
        source_agent_id: &str,
        scope: AgentInstallationScope,
        workspace: Option<&str>,
    ) -> AgentInstallationRow {
        AgentInstallationRow {
            installation_id: uuid::Uuid::now_v7(),
            scope,
            canonical_workspace_id: workspace.map(str::to_owned),
            source_agent_id: source_agent_id.into(),
            source_identity: "owned-path-test".into(),
            source_revision: None,
            source_digest: "digest".into(),
            fetched_at_unix_ms: 0,
            installation_revision: 1,
            deleted_at_unix_ms: None,
        }
    }

    fn observation(installation: &AgentInstallationRow) -> AgentObservationRow {
        AgentObservationRow {
            installation_id: installation.installation_id,
            observed_digest: installation.source_digest.clone(),
            observation_revision: 1,
            reviewed: true,
            observed_at_unix_ms: 0,
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let local = tmp.path().join("local.md");
    fs::write(
        &local,
        "---\ndescription: local\nschemaVersion: 2\nagentId: local/00000000-0000-0000-0000-000000000003\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 8\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nbody\n",
    )
    .unwrap();
    let global = installation(
        "local/00000000-0000-0000-0000-000000000003",
        AgentInstallationScope::Global,
        None,
    );
    assert!(
        load_profile_definition_from_owned_path(
            global.clone(),
            observation(&global),
            AgentProfileInstallationSource::Global,
            &local,
        )
        .is_ok()
    );

    let shared = installation(
        "authored/shared",
        AgentInstallationScope::WorkspaceShared,
        Some("workspace"),
    );
    assert!(
        load_profile_definition_from_owned_path(
            shared.clone(),
            observation(&shared),
            AgentProfileInstallationSource::WorkspaceShared,
            &local,
        )
        .is_err()
    );
    let authored = tmp.path().join("shared.md");
    fs::write(
        &authored,
        "---\ndescription: shared\nschemaVersion: 2\nagentId: authored/shared\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 8\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\nbody\n",
    )
    .unwrap();
    assert!(
        load_profile_definition_from_owned_path(
            shared.clone(),
            observation(&shared),
            AgentProfileInstallationSource::WorkspaceShared,
            &authored,
        )
        .is_ok()
    );
}

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

fn trusted_policy(root: &Path) -> crate::config::trust::WorkspaceTrustPolicy {
    crate::config::trust::WorkspaceTrustPolicy {
        root: crate::config::trust::resolve_trust_root(root).unwrap(),
        mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
    }
}

fn trusted_resolve(root: &Path, name: &str) -> Result<Option<AgentDef>> {
    crate::config::trust::with_workspace_trust_policy(trusted_policy(root), || resolve(root, name))
}

fn trusted_list_all(root: &Path) -> Vec<AgentListing> {
    crate::config::trust::with_workspace_trust_policy(trusted_policy(root), || list_all(root))
}

fn trusted_eject_builtin(
    root: &Path,
    config_dir: &Path,
    name: &str,
) -> Result<(std::path::PathBuf, bool)> {
    crate::config::trust::with_workspace_trust_policy(trusted_policy(root), || {
        eject_builtin(root, config_dir, name)
    })
}

fn trusted_reset_all_builtins(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    crate::config::trust::with_workspace_trust_policy(trusted_policy(root), || {
        reset_all_builtins(root)
    })
}

#[test]
fn configured_agent_dirs_resolve_relative_to_defining_config_file() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("project").join(".cockpit");
    fs::create_dir_all(&config_dir).unwrap();
    let config = config_dir.join("config.json");
    fs::write(&config, r#"{"agent_dirs":["relative-agents"]}"#).unwrap();

    let dirs =
        crate::config::trust::with_workspace_trust_policy(trusted_policy(tmp.path()), || {
            configured_agent_dirs_for_paths(std::slice::from_ref(&config))
        });

    assert_eq!(dirs, vec![config_dir.join("relative-agents")]);
}

// ── Parsing ──────────────────────────────────────────────────────────────

fn vnext_document(extra_frontmatter: &str) -> String {
    format!(
        "---\ndescription: Reviewer\nschemaVersion: 2\nagentId: authored/reviewer\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Review source changes\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n{extra_frontmatter}---\nbody\n"
    )
}

fn vnext_agent_document(description: &str, body: &str) -> String {
    format!(
        "---\ndescription: {description}\nschemaVersion: 2\nagentId: authored/reviewer\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: Review source changes\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n---\n\n{body}\n"
    )
}

fn builtin_override_document(name: &str, description: &str, body: &str) -> String {
    let mut definition = embedded_default(name).expect("known bundled definition");
    definition.description = description.to_string();
    definition.prompt = body.to_string();
    definition.prompt_overrides.clear();
    definition.to_markdown().expect("vNext bundled override")
}

#[test]
fn agent_vnext_parse_round_trip_preserves_advisory_model_metadata() {
    let text = r#"---
description: Reviewer
schemaVersion: 2
agentId: authored/reviewer
executionKind: coding
modelSlots:
  primary:
    purpose: Review source changes
    minContextTokens: 32768
    requiredCapabilities: [text_generation, tool_calling]
    locality: any
    allowDefaultFallback: false
    suggestedModels:
      - recommendationId: claude-sonnet
        upstreamIdentity: anthropic/claude-sonnet
        providerAliases:
          - providerId: anthropic
            modelId: claude-sonnet-4
        authorLabel: Sonnet
        rationale: Strong code review
questions:
  autoAnswer: recommended_low_risk
  decisionTimeoutSeconds: 30
  resolverOrder: warm_parent_then_utility
  neverAutoResolve: [authorization, credential]
---

Review only the declared scope.
"#;

    let parsed = parse_agent(text, "reviewer", "reviewer.md".into()).unwrap();
    let vnext = parsed.vnext.as_ref().expect("v2 definition");
    assert_eq!(vnext.agent_id, "authored/reviewer");
    assert_eq!(vnext.model_slots["primary"].suggested_models.len(), 1);
    assert_eq!(
        vnext.model_slots["primary"].suggested_models[0].recommendation_id,
        "claude-sonnet"
    );
    assert_eq!(
        parse_agent(
            &parsed.to_markdown().unwrap(),
            "reviewer",
            "reviewer.md".into()
        )
        .unwrap()
        .vnext,
        parsed.vnext
    );
}

#[test]
fn agent_vnext_rejects_legacy_authority_fields_and_unsorted_capabilities() {
    let authority = r#"---
schemaVersion: 2
agentId: authored/reviewer
executionKind: coding
modelSlots:
  primary:
    purpose: Review source changes
    minContextTokens: 1
    requiredCapabilities: [text_generation]
    locality: any
    allowDefaultFallback: false
tools: [write]
---
body
"#;
    assert!(parse_agent(authority, "reviewer", "reviewer.md".into()).is_err());

    let unsorted = authority.replace("tools: [write]\n", "").replace(
        "requiredCapabilities: [text_generation]",
        "requiredCapabilities: [tool_calling, text_generation]",
    );
    assert!(parse_agent(&unsorted, "reviewer", "reviewer.md".into()).is_err());
}

#[test]
fn agent_vnext_rejects_empty_duplicate_and_unknown_capabilities() {
    let base = vnext_document("");
    for invalid in [
        base.replace("[text_generation]", "[]"),
        base.replace("[text_generation]", "[text_generation, text_generation]"),
        base.replace("[text_generation]", "[unbounded_authority]"),
    ] {
        assert!(parse_agent(&invalid, "reviewer", "reviewer.md".into()).is_err());
    }
}

#[test]
fn agent_vnext_rejects_legacy_keys_by_raw_presence_even_when_default_or_null() {
    let base = r#"---
schemaVersion: 2
agentId: authored/reviewer
executionKind: coding
modelSlots:
  primary:
    purpose: Review source changes
    minContextTokens: 1
    requiredCapabilities: [text_generation]
    locality: any
    allowDefaultFallback: false
---
body
"#;
    for legacy in [
        "mode: all",
        "forkEligible: false",
        "tools: null",
        "model: null",
    ] {
        let invalid = base.replacen("---\nbody", &format!("{legacy}\n---\nbody"), 1);
        assert!(
            parse_agent(&invalid, "reviewer", "reviewer.md".into()).is_err(),
            "v2 accepted legacy key {legacy}"
        );
    }
}

#[test]
fn agent_vnext_canonical_digest_bytes_ignore_authored_mapping_order() {
    let first_source = r#"---
schemaVersion: 2
agentId: authored/reviewer
executionKind: coding
modelSlots:
  primary:
    purpose: Review source changes
    minContextTokens: 1
    requiredCapabilities: [text_generation]
    locality: any
    allowDefaultFallback: false
description: Reviewer
---
body
"#;
    let reordered_source = r#"---
description: Reviewer
modelSlots:
  primary:
    allowDefaultFallback: false
    locality: any
    requiredCapabilities: [text_generation]
    minContextTokens: 1
    purpose: Review source changes
executionKind: coding
agentId: authored/reviewer
schemaVersion: 2
---
body
"#;
    let first = parse_agent(first_source, "reviewer", "reviewer.md".into()).unwrap();
    let reordered = parse_agent(reordered_source, "reviewer", "reviewer.md".into()).unwrap();
    assert_eq!(
        first.vnext_digest_bytes().unwrap(),
        reordered.vnext_digest_bytes().unwrap()
    );
    let different_body = parse_agent(
        &reordered_source.replace("---\nbody", "---\na different body"),
        "reviewer",
        "reviewer.md".into(),
    )
    .unwrap();
    assert_ne!(
        first.vnext_digest_bytes().unwrap(),
        different_body.vnext_digest_bytes().unwrap(),
        "the markdown body is part of the canonical definition digest"
    );
}

#[test]
fn agent_vnext_rejects_schema_less_user_definitions_and_null_delegation() {
    let schema_less = r#"---
description: legacy
mode: subagent
---
legacy body
"#;
    assert!(parse_agent(schema_less, "legacy", "legacy.md".into()).is_err());

    let null_delegation = r#"---
schemaVersion: 2
agentId: authored/reviewer
executionKind: coding
modelSlots:
  primary:
    purpose: Review source changes
    minContextTokens: 1
    requiredCapabilities: [text_generation]
    locality: any
    allowDefaultFallback: false
delegation: null
---
body
"#;
    assert!(parse_agent(null_delegation, "reviewer", "reviewer.md".into()).is_err());
}

#[test]
fn agent_vnext_workspace_definition_cannot_claim_daemon_local_publisher() {
    let text = r#"---
description: Private reviewer
schemaVersion: 2
agentId: local/00000000-0000-0000-0000-000000000001
executionKind: coding
modelSlots:
  primary:
    purpose: Review source changes
    minContextTokens: 1
    requiredCapabilities: [text_generation]
    locality: any
    allowDefaultFallback: false
delegation:
  allowedChildren:
    - kind: local_installation
      installationId: 00000000-0000-0000-0000-000000000001
  maxDescendantDepth: 1
  maxConcurrentChildren: 1
  targets: [same_root]
---
body
"#;
    let err = parse_agent(text, "private-reviewer", "workspace.md".into()).unwrap_err();
    assert!(err.to_string().contains("daemon-local"), "{err}");
}

#[test]
fn agent_vnext_rejects_duplicate_slots_and_invalid_delegation_combinations() {
    let duplicate_slots = vnext_document(
        "  primary:\n    purpose: Duplicate\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n",
    );
    assert!(parse_agent(&duplicate_slots, "reviewer", "reviewer.md".into()).is_err());

    for delegation in [
        // Computer agents are always leaves.
        "executionKind: computer\ndelegation:\n  allowedChildren: [{ kind: portable_ref, ref: authored/child }]\n  maxDescendantDepth: 1\n  maxConcurrentChildren: 1\n  targets: [same_root]\n",
        // Worktree and same-root are contradictory target authority.
        "delegation:\n  allowedChildren: [{ kind: portable_ref, ref: authored/child }]\n  maxDescendantDepth: 1\n  maxConcurrentChildren: 1\n  targets: [same_root, managed_worktree]\n",
    ] {
        let text = if delegation.starts_with("executionKind") {
            vnext_document("").replacen("executionKind: coding\n", delegation, 1)
        } else {
            vnext_document(delegation)
        };
        assert!(parse_agent(&text, "reviewer", "reviewer.md".into()).is_err());
    }
}

#[test]
fn agent_vnext_recommendation_aliases_are_ordered_exact_and_authority_free() {
    let valid = vnext_document(
        "    suggestedModels:\n      - recommendationId: alpha\n        upstreamIdentity: acme/model-one\n        providerAliases:\n          - providerId: provider-a\n            modelId: model-a\n          - providerId: provider-b\n            modelId: model-b\n      - recommendationId: beta\n        upstreamIdentity: acme/model-two\n",
    );
    let parsed = parse_agent(&valid, "reviewer", "reviewer.md".into()).unwrap();
    assert_eq!(
        parsed.vnext.unwrap().model_slots["primary"]
            .suggested_models
            .iter()
            .map(|recommendation| recommendation.recommendation_id.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "beta"]
    );

    for invalid in [
        valid.replace(
            "providerId: provider-a\n            modelId: model-a",
            "providerId: provider-b\n            modelId: model-b",
        ),
        valid.replace("providerId: provider-a", "providerId: \" provider-a\""),
        valid.replace("upstreamIdentity: acme/model-one", "credential: secret"),
        valid.replace("recommendationId: alpha", "providerProfile: private"),
    ] {
        assert!(parse_agent(&invalid, "reviewer", "reviewer.md".into()).is_err());
    }
}

#[test]
fn agent_vnext_selector_schema_is_exact_and_closed() {
    let valid = vnext_document(
        "verification:\n  rules:\n    - selector:\n        allOf: [{ toolClass: artifact_write }]\n        anyOf: [{ toolId: write }, { namespace: mcp/server }]\n      action: verify\n      adjudicatorSlot: primary\n",
    );
    assert!(parse_agent(&valid, "reviewer", "reviewer.md".into()).is_ok());

    for invalid in [
        valid.replace("allOf: [{ toolClass: artifact_write }]\n        anyOf: [{ toolId: write }, { namespace: mcp/server }]", "allOf: []"),
        valid.replace("{ toolId: write }", "{ toolName: write }"),
        valid.replace("{ toolId: write }, { namespace: mcp/server }", "{ toolId: write }, { toolId: write }"),
        valid.replace("{ toolId: write }", "{ toolId: Write* }"),
        valid.replace("action: verify\n      adjudicatorSlot: primary", "action: off\n      maxCandidates: 1"),
        valid.replace("adjudicatorSlot: primary\n", ""),
    ] {
        assert!(parse_agent(&invalid, "reviewer", "reviewer.md".into()).is_err());
    }
}

#[test]
fn agent_vnext_rejects_enabled_question_auto_answer_without_timeout() {
    let invalid = vnext_document(
        "questions:\n  autoAnswer: recommended_low_risk\n  resolverOrder: warm_parent_then_utility\n",
    );
    assert!(parse_agent(&invalid, "reviewer", "reviewer.md".into()).is_err());
}

#[test]
fn agent_vnext_rejects_legacy_frontmatter_contract() {
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
    let error = parse_agent(text, "my-reviewer", "x.md".into())
        .unwrap_err()
        .to_string();
    assert!(error.contains("schemaVersion: 2"), "{error}");
}

#[test]
fn agent_vnext_rejects_fork_eligible_legacy_frontmatter() {
    let text = r#"---
description: Forkable agent.
mode: subagent
forkEligible: true
---

Body.
"#;

    let error = parse_agent(text, "forker", "forker.md".into())
        .unwrap_err()
        .to_string();
    assert!(error.contains("schemaVersion: 2"), "{error}");
}

#[test]
fn agent_vnext_rejects_missing_schema_version_instead_of_defaulting_mode() {
    let text = "---\ndescription: x\n---\nbody\n";
    let error = parse_agent(text, "a", "a.md".into())
        .unwrap_err()
        .to_string();
    assert!(error.contains("schemaVersion: 2"), "{error}");
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
fn load_from_dir_rejects_oversized_override_markdown() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("agents");
    let agent_dir = dir.join("large");
    fs::create_dir_all(&agent_dir).unwrap();
    // The directory form reads per-model override files (`<key>.md`); an
    // oversized override is rejected just like an oversized flat file.
    write_large_agent(&agent_dir.join("m1.md"), MAX_MARKDOWN_BYTES + 1);

    let err = load_from_dir(&dir, "large").unwrap_err();

    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[test]
fn list_all_excludes_oversized_custom_agent() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    fs::write(dir.join("small.md"), vnext_agent_document("small", "body")).unwrap();
    write_large_agent(&dir.join("large.md"), MAX_MARKDOWN_BYTES + 1);

    let names: Vec<String> = trusted_list_all(tmp.path())
        .into_iter()
        .map(|a| a.name)
        .collect();

    assert!(names.iter().any(|name| name == "small"), "{names:?}");
    assert!(!names.iter().any(|name| name == "large"), "{names:?}");
}

// ── Round-trip / eject faithfulness ──────────────────────────────────────

#[test]
fn to_markdown_round_trips_through_parse() {
    let def = embedded_default("builder").unwrap();
    let md = def.to_markdown().unwrap();
    // Re-parse the ejected form.
    let parsed = parse_agent_with_scope(
        &md,
        "builder",
        "builder.md".into(),
        DefinitionScope::BuiltinOverride,
    )
    .unwrap();
    assert_eq!(parsed.description, def.description);
    assert_eq!(parsed.vnext, def.vnext);
    // Ejection serializes the user-authorable v2 contract only. Built-in
    // tool surfaces stay host-owned factory data and cannot become frontmatter
    // authority by round-tripping through an editable file.
    assert!(parsed.tools.is_none());
    assert!(parsed.scan_tool_results.is_none());
    assert_eq!(parsed.prompt, def.prompt);
}

#[test]
fn agent_vnext_every_editable_builtin_ejects_closed_schema_v2() {
    for &name in crate::agents::BUILTIN_AGENT_NAMES {
        let embedded = embedded_default(name).unwrap();
        let markdown = embedded.to_markdown().unwrap();
        assert!(markdown.contains("schemaVersion: 2"), "{name}");
        assert!(
            parse_agent_with_scope(
                &markdown,
                name,
                format!("{name}.md").into(),
                DefinitionScope::BuiltinOverride,
            )
            .is_ok(),
            "{name}"
        );
    }
}

#[test]
fn legacy_tool_tier_frontmatter_is_rejected() {
    let text = r#"---
description: Tiered agent
mode: subagent
tools: [read, search, skill_manage]
toolTiers:
  read: enabled
  search: discoverable
  skill_manage: disabled
---

Body
"#;
    assert!(parse_agent(text, "tiered", "tiered.md".into()).is_err());
}

#[test]
fn tool_tier_enabled_label_round_trips() {
    assert_eq!(ToolTier::Enabled.label(), "enabled");
    assert_eq!(ToolTier::from_label("enabled"), Some(ToolTier::Enabled));
    assert_eq!(ToolTier::from_label("builtin"), None);

    let yaml = serde_yaml::to_string(&ToolTier::Enabled).unwrap();
    assert_eq!(yaml.trim(), "enabled");
    let reparsed: ToolTier = serde_yaml::from_str("enabled").unwrap();
    assert_eq!(reparsed, ToolTier::Enabled);
}

#[test]
fn legal_tool_tiers_excludes_disabled_for_safety_set() {
    for tool in ["question", "write"] {
        let tiers = crate::agents::legal_tool_tiers(tool);
        assert_eq!(tiers, &[ToolTier::Enabled], "{tool}");
        assert!(!tiers.contains(&ToolTier::Discoverable), "{tool}");
        assert!(!tiers.contains(&ToolTier::Disabled), "{tool}");
    }
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
        tool_tiers: std::collections::BTreeMap::new(),
        tool_descriptions: std::collections::BTreeMap::new(),
        scan_tool_results: None,
        goal_supervision: GoalSettingsOverride::default(),
        permission: None,
        capabilities: None,
        tool_steering: None,
        context_policy: None,
        vnext: None,
        prompt: "body".into(),
        prompt_overrides: std::collections::BTreeMap::new(),
        package_files: None,
        private_subagents: std::collections::BTreeMap::new(),
        source: "x.md".into(),
    }
}

#[test]
fn goal_settings_effective_resolution_session_over_agent_over_global() {
    let global = crate::config::extended::GoalSupervisionConfig {
        enabled: true,
        cold_skeptic_count: 3,
        cold_skeptic_model: Some("global/model".to_string()),
        max_verification_attempts: 2,
        ..Default::default()
    };
    let agent = GoalSettingsOverride {
        cold_skeptic_count: Some(4),
        cold_skeptic_model: Some("agent/model".to_string()),
        max_verification_attempts: Some(5),
        ..Default::default()
    };
    let session = GoalSettingsOverride {
        cold_skeptic_count: None,
        cold_skeptic_model: Some("session/model".to_string()),
        max_verification_attempts: None,
        ..Default::default()
    };

    let resolved = resolve_goal_supervision_config(Some(&session), Some(&agent), global);

    assert!(resolved.enabled, "global kill switch is non-overridable");
    assert_eq!(
        resolved.cold_skeptic_count, 4,
        "agent count overrides global"
    );
    assert_eq!(
        resolved.cold_skeptic_model.as_deref(),
        Some("session/model"),
        "session model overrides agent"
    );
    assert_eq!(
        resolved.max_verification_attempts, 5,
        "agent rounds override global"
    );
}

#[test]
fn goal_settings_override_rejects_invalid_values() {
    assert!(
        GoalSettingsOverride {
            cold_skeptic_count: Some(0),
            ..GoalSettingsOverride::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        GoalSettingsOverride {
            max_verification_attempts: Some(0),
            ..GoalSettingsOverride::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        GoalSettingsOverride {
            cold_skeptic_model: Some("not-a-selector".to_string()),
            ..GoalSettingsOverride::default()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn write_tools_are_role_driven_not_name_bound() {
    // Write/lock tools are no longer restricted to a single hard-coded writer
    // name (`builder`): any agent that names them is a write-capable agent
    // (prompt `lock-manager-multi-writer.md`). The single-writer guarantee is
    // upheld by the lock manager keyed by `(session, agent)`, not by a name
    // check at load. So a non-`builder` agent granting a write tool now
    // validates — its concurrent writes are arbitrated path-granular.
    let def = def_with_tools("custom-writer", &["read", "write"]);
    assert!(
        validate_invariants(&def).is_ok(),
        "any write-capable agent may hold write/lock tools"
    );
    // The full write/lock set is admissible too.
    let full = def_with_tools("custom-writer", LOCK_WRITE_TOOLS);
    assert!(validate_invariants(&full).is_ok());
}

#[test]
fn roster_trim_spawn_agents_drop_swarm_keep_bee() {
    // A non-`bee` agent naming the recursive fan-out tool is rejected on the
    // write branch; read-only Multireview/scout are the review exceptions.
    let def = def_with_tools("Build", &["read", "spawn"]);
    let err = validate_invariants(&def).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("`spawn`"), "{msg}");
    assert!(msg.contains("leaf-termination"), "{msg}");
    let mut ok = def_with_tools("Swarm", &["read", "spawn"]);
    ok.mode = AgentMode::Primary;
    assert!(validate_invariants(&ok).is_err());
    let bee = def_with_tools("bee", &["read", "spawn"]);
    assert!(validate_invariants(&bee).is_ok());
    assert!(
        embedded_default("bee")
            .unwrap()
            .tools
            .unwrap()
            .iter()
            .any(|tool| tool == "spawn")
    );
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
fn tool_tier_validation_rejects_non_granted_structural_and_lock_write() {
    let mut non_granted = def_with_tools("my-agent", &["read"]);
    non_granted
        .tool_tiers
        .insert("search".to_string(), ToolTier::Discoverable);
    let err = validate_invariants(&non_granted).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("`search`"), "{msg}");
    assert!(msg.contains("does not grant"), "{msg}");

    let mut structural = def_with_tools("my-agent", &["read", "question"]);
    structural
        .tool_tiers
        .insert("question".to_string(), ToolTier::Discoverable);
    let err = validate_invariants(&structural).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("`question`"), "{msg}");
    assert!(msg.contains("structural"), "{msg}");

    let mut lock_write = def_with_tools("writer", &["read", "write"]);
    lock_write
        .tool_tiers
        .insert("write".to_string(), ToolTier::Discoverable);
    let err = validate_invariants(&lock_write).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("`write`"), "{msg}");
    assert!(msg.contains("write/lock"), "{msg}");
}

#[test]
fn validate_invariants_rejects_disabled_safety_tool() {
    let mut structural = def_with_tools("my-agent", &["read", "question"]);
    structural
        .tool_tiers
        .insert("question".to_string(), ToolTier::Disabled);
    let err = validate_invariants(&structural).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("`question`"), "{msg}");
    assert!(msg.contains("disabled"), "{msg}");

    let mut lock_write = def_with_tools("writer", &["read", "write"]);
    lock_write
        .tool_tiers
        .insert("write".to_string(), ToolTier::Disabled);
    let err = validate_invariants(&lock_write).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("`write`"), "{msg}");
    assert!(msg.contains("disabled"), "{msg}");
}

#[test]
fn tool_tier_sandbox_only_tools_not_grantable_or_tierable() {
    for t in SANDBOX_ONLY_TOOLS {
        let grant = def_with_tools("my-agent", &["read", t]);
        let err = validate_invariants(&grant).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains(&format!("`{t}`")), "{msg}");
        assert!(msg.contains("docs-answerer-only"), "{msg}");

        let mut tier = def_with_tools("my-agent", &["read"]);
        tier.tool_tiers
            .insert((*t).to_string(), ToolTier::Discoverable);
        let err = validate_invariants(&tier).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains(&format!("`{t}`")), "{msg}");
        assert!(msg.contains("does not grant"), "{msg}");
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
    let def = trusted_resolve(tmp.path(), "builder").unwrap().unwrap();
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
        builtin_override_document("builder", "edited builder", "NEW BODY"),
    )
    .unwrap();
    let def = trusted_resolve(tmp.path(), "builder").unwrap().unwrap();
    assert!(!def.source.as_os_str().is_empty(), "override has a source");
    assert_eq!(def.description, "edited builder");
    assert_eq!(def.prompt, "NEW BODY");
    assert!(def.vnext.is_some());
    assert!(def.tools.is_none());
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
        let env = crate::test_env::lock();
        env.set_cockpit_config(&cfg_path);
        agent_search_dirs(tmp.path())
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
        builtin_override_document("explore", "my explore", "body"),
    )
    .unwrap();
    let listings = trusted_list_all(tmp.path());
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
    assert!(
        trusted_resolve(tmp.path(), "no-such-agent")
            .unwrap()
            .is_none()
    );
}

#[test]
fn resolve_malformed_override_fails_loudly() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    let path = dir.join("builder.md");
    fs::write(&path, "---\nmode: subagent\n---\nno description\n").unwrap();
    let err = trusted_resolve(tmp.path(), "builder").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("builder.md"), "names the source: {msg}");
    // Did NOT silently fall back to the embedded default.
}

#[test]
fn resolve_rejects_override_with_invariant_violation() {
    // Legacy authority-bearing override frontmatter is rejected at resolve
    // time (it never silently falls back to the embedded default).
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    fs::write(
        dir.join("explore.md"),
        "---\ndescription: e\ntools: [read, glob]\n---\nbody\n",
    )
    .unwrap();
    let err = trusted_resolve(tmp.path(), "explore").unwrap_err();
    assert!(format!("{err}").contains("schemaVersion: 2"));
}

// ── list_all ─────────────────────────────────────────────────────────────

#[test]
fn list_all_lists_builtins_and_custom() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    fs::write(
        dir.join("my-reviewer.md"),
        vnext_agent_document("reviewer", "body"),
    )
    .unwrap();
    let listings = trusted_list_all(tmp.path());
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
    let (path, written) = trusted_eject_builtin(tmp.path(), &config_dir, "builder").unwrap();
    assert!(written, "first eject writes a new file");
    assert!(path.exists());
    let on_disk = fs::read_to_string(&path).unwrap();
    // A bundled `cockpit/` identity is accepted only through the trusted
    // built-in override resolver, never by the public workspace parser.
    assert!(parse_agent(&on_disk, "builder", path.clone()).is_err());
    let parsed = parse_agent_with_scope(
        &on_disk,
        "builder",
        path.clone(),
        DefinitionScope::BuiltinOverride,
    )
    .unwrap();
    let embedded = embedded_default("builder").unwrap();
    assert_eq!(parsed.description, embedded.description);
    assert_eq!(parsed.vnext, embedded.vnext);
    assert!(parsed.tools.is_none());
    assert_eq!(parsed.prompt, embedded.prompt);
    // And the ejected file is now the resolved override.
    let resolved = trusted_resolve(tmp.path(), "builder").unwrap().unwrap();
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
        builtin_override_document("builder", "mine", "MY EDITS"),
    )
    .unwrap();
    let (path, written) = trusted_eject_builtin(tmp.path(), &config_dir, "builder").unwrap();
    assert!(!written, "must not clobber");
    assert_eq!(path, existing);
    // The user's content is intact.
    assert!(fs::read_to_string(&existing).unwrap().contains("MY EDITS"));
}

#[test]
fn eject_rejects_non_builtin() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join(".cockpit");
    assert!(trusted_eject_builtin(tmp.path(), &config_dir, "my-custom").is_err());
}

// ── Reset ────────────────────────────────────────────────────────────────

#[test]
fn reset_all_removes_builtin_overrides_only() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    // Two built-in overrides + one custom agent.
    fs::write(
        dir.join("builder.md"),
        builtin_override_document("builder", "c", "b"),
    )
    .unwrap();
    fs::write(
        dir.join("explore.md"),
        builtin_override_document("explore", "e", "b"),
    )
    .unwrap();
    fs::write(dir.join("my-reviewer.md"), vnext_agent_document("r", "b")).unwrap();

    let removed = trusted_reset_all_builtins(tmp.path()).unwrap();
    assert_eq!(removed.len(), 2, "only the two built-in overrides removed");
    assert!(!dir.join("builder.md").exists());
    assert!(!dir.join("explore.md").exists());
    assert!(
        dir.join("my-reviewer.md").exists(),
        "custom agent is untouched by reset"
    );
    // Built-ins now resolve from embedded again.
    assert!(
        trusted_resolve(tmp.path(), "builder")
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
    let removed = trusted_reset_all_builtins(tmp.path()).unwrap();
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
    // A `<name>/` directory is the per-model override layout.
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
    // When both a flat `<name>.md` and a per-model `<name>/` directory exist,
    // the richer directory form wins — it falls back to the flat sibling
    // internally for any absent mode.
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("rev.md"), "x").unwrap();
    let dir = tmp.path().join("rev");
    fs::create_dir_all(&dir).unwrap();
    assert_eq!(agent_path_in(tmp.path(), "rev"), dir);
}

// ── Per-model directory-form resolution ───────────────────────────────────

/// Write a per-model override agent markdown file (frontmatter + body) into
/// `<agents>/<name>/<key>.md`.
fn write_override_file(agents: &Path, name: &str, key: &str, body: &str) {
    let dir = agents.join(name);
    let path = dir.join(format!("{key}.md"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let text = vnext_agent_document("A custom agent.", body);
    fs::write(path, text).unwrap();
}

#[test]
fn dir_form_selects_per_model_override() {
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    write_override_file(&agents, "rev", "anthropic/claude-opus", "OPUS BODY");
    write_override_file(&agents, "rev", "openai/gpt-5", "GPT BODY");
    fs::write(
        agents.join("rev.md"),
        vnext_agent_document("Flat canonical.", "FLAT BODY"),
    )
    .unwrap();

    let def = trusted_resolve(tmp.path(), "rev")
        .unwrap()
        .expect("agent resolves");
    assert_eq!(
        def.resolved_prompt(Some("anthropic/claude-opus")),
        "OPUS BODY"
    );
    assert_eq!(def.resolved_prompt(Some("openai/gpt-5")), "GPT BODY");
    assert_eq!(def.resolved_prompt_for_model("openai", "gpt-5"), "GPT BODY");
    // No hint → the canonical flat body.
    assert_eq!(def.resolved_prompt(None), "FLAT BODY");
}

#[test]
fn dir_form_primary_slot_override_is_used_for_unlisted_model() {
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    write_override_file(&agents, "rev", "primary", "PRIMARY BODY");
    fs::write(
        agents.join("rev.md"),
        vnext_agent_document("Flat canonical.", "FLAT BODY"),
    )
    .unwrap();

    let def = trusted_resolve(tmp.path(), "rev")
        .unwrap()
        .expect("agent resolves");
    assert_eq!(
        def.resolved_prompt_for_model("unknown", "model"),
        "PRIMARY BODY"
    );
}

#[test]
fn dir_form_unknown_model_hint_falls_back_to_flat() {
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    write_override_file(&agents, "rev", "anthropic/claude-opus", "OPUS BODY");
    fs::write(
        agents.join("rev.md"),
        vnext_agent_document("Flat canonical.", "FLAT BODY"),
    )
    .unwrap();

    let def = trusted_resolve(tmp.path(), "rev")
        .unwrap()
        .expect("agent resolves");
    // An unknown model hint falls back to the canonical flat body.
    assert_eq!(def.resolved_prompt(Some("unknown/model")), "FLAT BODY");
    assert_eq!(def.resolved_prompt(None), "FLAT BODY");
}

#[test]
fn dir_form_override_only_no_flat_uses_first_override_as_canonical() {
    // A directory with override files but no flat sibling still loads: the
    // first override body is the canonical fallback.
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    write_override_file(&agents, "rev", "anthropic/claude-opus", "OPUS BODY");
    let def = trusted_resolve(tmp.path(), "rev")
        .unwrap()
        .expect("agent resolves");
    // The override is present and selectable.
    assert_eq!(
        def.resolved_prompt(Some("anthropic/claude-opus")),
        "OPUS BODY"
    );
    // No hint and no flat → the first override body is the canonical body.
    assert!(def.resolved_prompt(None).len() > 0);
}

#[test]
fn dir_form_empty_directory_errors_naming_agent() {
    // A `<name>/` directory with no override files and no flat sibling is
    // malformed: error naming the agent.
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    fs::create_dir_all(agents.join("rev")).unwrap();
    let err = trusted_resolve(tmp.path(), "rev").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("rev"), "names the agent: {msg}");
}

#[test]
fn flat_file_agent_has_no_overrides() {
    // A flat-file agent has no per-model overrides — the same body serves
    // every model hint.
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    fs::write(
        agents.join("rev.md"),
        vnext_agent_document("Single body.", "ONE BODY"),
    )
    .unwrap();
    let def = trusted_resolve(tmp.path(), "rev")
        .unwrap()
        .expect("agent resolves");
    assert_eq!(def.resolved_prompt(None), "ONE BODY");
    assert_eq!(def.resolved_prompt(Some("any/model")), "ONE BODY");
    assert!(def.prompt_overrides.is_empty());
}

#[test]
fn embedded_builtin_resolves_to_canonical_body() {
    // An embedded built-in has no per-model overrides; resolved_prompt always
    // returns the canonical body regardless of the model hint.
    let def = embedded_default("Build").unwrap();
    let body = def.prompt.clone();
    assert_eq!(def.resolved_prompt(None), body);
    assert_eq!(def.resolved_prompt(Some("any/model")), body);
    assert!(def.prompt_overrides.is_empty());
}

#[test]
fn dir_form_enforces_invariants_at_load() {
    // Legacy authority-bearing frontmatter is rejected in directory form too.
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    let dir = agents.join("rev");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("defensive.md"),
        "---\ndescription: x\nmode: subagent\ntools: [read, grep]\n---\n\nB\n",
    )
    .unwrap();
    let err = trusted_resolve(tmp.path(), "rev").unwrap_err();
    assert!(format!("{err}").contains("schemaVersion: 2"), "{err}");
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
    let order = chat_ownable_primaries_with(tmp.path());
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
fn roster_trim_chat_ownable_lists_public_primaries() {
    let tmp = tempfile::tempdir().unwrap();
    project_agents_dir(tmp.path());

    let order = chat_ownable_primaries_with(tmp.path());
    assert_eq!(order, vec!["Plan", "Build", "Careful"]);
}

#[test]
fn roster_trim_auto_and_swarm_removed() {
    assert!(!BUILTIN_AGENT_NAMES.contains(&"Auto"));
    assert!(!BUILTIN_AGENT_NAMES.contains(&"Swarm"));
    assert!(!is_builtin_agent("Auto"));
    assert!(!is_builtin_agent("Swarm"));
    assert!(embedded_default("Auto").is_none());
    assert!(embedded_default("Swarm").is_none());
    assert!(is_removed_primary("Auto"));
    assert!(is_removed_primary("Swarm"));
}

#[test]
fn roster_trim_removed_builtin_override_file_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = project_agents_dir(tmp.path());
    for name in ["Auto", "Swarm"] {
        fs::write(
            dir.join(format!("{name}.md")),
            "---\ndescription: removed primary override\nmode: primary\n---\nbody\n",
        )
        .unwrap();

        assert!(
            trusted_resolve(tmp.path(), name).unwrap().is_none(),
            "removed builtin {name} override must not resolve"
        );
    }

    let listed: Vec<String> = trusted_list_all(tmp.path())
        .into_iter()
        .map(|a| a.name)
        .collect();
    assert!(
        !listed.iter().any(|name| name == "Auto" || name == "Swarm"),
        "removed builtin overrides must not appear in list_all: {listed:?}"
    );
}

#[test]
fn next_primary_in_cycle_wraps_builtins_only() {
    let order: Vec<String> = vec!["Plan".into(), "Build".into(), "Careful".into()];
    assert_eq!(next_primary_in_cycle("Plan", &order), "Build");
    assert_eq!(next_primary_in_cycle("Build", &order), "Careful");
    assert_eq!(next_primary_in_cycle("Careful", &order), "Plan");
}

#[test]
fn next_primary_in_cycle_wraps_through_user_primaries() {
    let order: Vec<String> = vec![
        "Plan".into(),
        "Build".into(),
        "Careful".into(),
        "alpha".into(),
        "zeta".into(),
    ];
    assert_eq!(next_primary_in_cycle("Build", &order), "Careful");
    assert_eq!(next_primary_in_cycle("Careful", &order), "alpha");
    assert_eq!(next_primary_in_cycle("alpha", &order), "zeta");
    // The last user primary wraps back to the front of the cycle.
    assert_eq!(next_primary_in_cycle("zeta", &order), "Plan");
}

#[test]
fn shift_tab_cycle_wraps_public_builtins() {
    let order: Vec<String> = vec!["Plan".into(), "Build".into(), "Careful".into()];
    let mut cur = "Plan".to_string();
    let mut visited = Vec::new();
    for _ in 0..order.len() {
        cur = next_primary_in_cycle(&cur, &order);
        visited.push(cur.clone());
    }
    assert_eq!(visited, vec!["Build", "Careful", "Plan"]);
    let mut cur = "Plan".to_string();
    for expected in ["Build", "Careful", "Plan", "Build"] {
        cur = next_primary_in_cycle(&cur, &order);
        assert_eq!(cur, expected, "cycle stalled after {cur}");
    }
}

#[test]
fn next_primary_in_cycle_off_cycle_starts_at_front() {
    let order: Vec<String> = vec!["Plan".into(), "Build".into(), "Careful".into()];
    // A subagent / stale name isn't in the cycle — start at the front.
    assert_eq!(next_primary_in_cycle("builder", &order), "Plan");
    // An empty cycle is a no-op (returns the current name unchanged).
    assert_eq!(next_primary_in_cycle("Build", &[]), "Build");
}

// ── Per-agent tool-description overrides ────────────────────────────────────

#[test]
fn legacy_tool_description_frontmatter_is_rejected() {
    // Raw string so the YAML indentation is preserved literally (a `\`
    // line-continuation would eat the leading spaces and flatten the map).
    let text = r#"---
description: A custom builder.
mode: primary
tools: [read, task]
tool_descriptions:
  read:
    normal: "Read the file you will edit yourself."
  task:
    normal: "Delegate substantive work here."
    frontier: "Delegate only when the work is separable."
    defensive: "Hand each well-scoped piece to a subagent in its own context."
---

Body.
"#;
    assert!(parse_agent(text, "builder", "x.md".into()).is_err());
}

#[test]
fn bare_string_tool_description_is_accepted() {
    let text = r#"---
description: A custom builder.
schemaVersion: 2
agentId: authored/builder
executionKind: coding
modelSlots:
  primary:
    purpose: Execute a coding task
    minContextTokens: 1
    requiredCapabilities: [text_generation]
    locality: any
    allowDefaultFallback: false
tool_descriptions:
  grep: "Search differently."
---

Body.
"#;
    let def = parse_agent(text, "builder", "x.md".into()).expect("bare string accepted");
    assert_eq!(
        def.tool_descriptions.get("grep"),
        Some(&ToolDescriptionSpec::Text(
            "Search differently.".to_string()
        ))
    );
}

#[test]
fn legacy_partial_tool_description_frontmatter_is_rejected() {
    let text = r#"---
description: A custom builder.
mode: primary
tools: [grep]
tool_descriptions:
  grep:
    defensive: "Search with explicit defensive guidance."
---

Body.
"#;
    assert!(parse_agent(text, "builder", "x.md".into()).is_err());
}

#[test]
fn unknown_tool_description_mode_key_is_rejected() {
    let text = r#"---
description: A custom builder.
schemaVersion: 2
agentId: authored/builder
executionKind: coding
modelSlots:
  primary:
    purpose: Execute a coding task
    minContextTokens: 1
    requiredCapabilities: [text_generation]
    locality: any
    allowDefaultFallback: false
tool_descriptions:
  grep:
    normal: "Search differently."
---

Body.
"#;
    let err = parse_agent(text, "builder", "x.md".into()).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("tool_descriptions.grep:"), "{msg}");
    assert!(
        msg.contains("unknown tool-description key `normal`"),
        "{msg}"
    );
    assert_eq!(
        msg.matches("tool_descriptions.grep:").count(),
        1,
        "nested field path must not be duplicated: {msg}"
    );
}

#[test]
fn legacy_tool_descriptions_do_not_round_trip_through_vnext() {
    let text = r#"---
description: A custom builder.
mode: subagent
tools: [read]
tool_descriptions:
  read:
    normal: "do-it-yourself wording"
    defensive: "defensive do-it-yourself wording"
---

Body.
"#;
    assert!(parse_agent(text, "builder", "x.md".into()).is_err());
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
  bash:
    normal: "nope, not granted"
---
Body.
"#;
    assert!(parse_agent(text, "builder", "x.md".into()).is_err());
}

#[test]
fn tool_description_override_for_unknown_tool_is_rejected() {
    let text = r#"---
description: d
mode: subagent
tools: [read]
tool_descriptions:
  not_a_tool:
    normal: "x"
---
Body.
"#;
    assert!(parse_agent(text, "builder", "x.md".into()).is_err());
}

#[test]
fn apply_tool_surface_override_replaces_tools_and_tiers() {
    let mut def = def_with_tools("worker", &["read", "bash"]);
    let selection = ToolSurfaceSelection {
        tools: vec![
            "read".to_string(),
            "mcp".to_string(),
            "session_search".to_string(),
        ],
        tool_tiers: std::collections::BTreeMap::from([(
            "session_search".to_string(),
            ToolTier::Discoverable,
        )]),
    };

    apply_tool_surface_override(&mut def, &selection).unwrap();

    assert_eq!(def.tools.as_deref(), Some(selection.tools.as_slice()));
    assert_eq!(def.tool_tiers, selection.tool_tiers);
}

#[test]
fn apply_tool_surface_override_rejects_invalid_surface() {
    let mut def = def_with_tools("worker", &["read"]);
    let selection = ToolSurfaceSelection {
        tools: vec!["read".to_string()],
        tool_tiers: std::collections::BTreeMap::from([(
            "session_search".to_string(),
            ToolTier::Discoverable,
        )]),
    };

    let err = apply_tool_surface_override(&mut def, &selection).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("does not grant"), "{msg}");
    assert!(msg.contains("session_search"), "{msg}");
    assert_eq!(def.tools.as_deref(), Some(&["read".to_string()][..]));
    assert!(def.tool_tiers.is_empty());
}

#[test]
fn docs_answerer_keeps_grep_and_glob_verbose_descriptions() {
    use crate::engine::tool::{Tool, definition_of};
    use crate::tools::{glob::GlobTool, grep::GrepTool};

    let def = super::builtin_defs::embedded_internal_default("docs-answerer").unwrap();

    let grep_override = def.tool_descriptions.get("grep").unwrap().to_override();
    let grep = GrepTool;
    let grep_docs_text = "Search file contents in this dependency package for a regex; with no shell here, use it to locate code before reading matches.";
    // Terse steering renders the override's canonical (normal) text.
    assert_eq!(
        definition_of(
            &grep,
            crate::agents::ToolSteering::Terse,
            Some(&grep_override)
        )
        .description,
        grep_docs_text
    );
    // Verbose steering: no verbose_text in the override, so it falls back to
    // the tool's own verbose description.
    assert_eq!(
        definition_of(
            &grep,
            crate::agents::ToolSteering::Verbose,
            Some(&grep_override)
        )
        .description,
        grep.verbose_description().unwrap()
    );

    let glob_override = def.tool_descriptions.get("glob").unwrap().to_override();
    let glob = GlobTool;
    assert_eq!(
        definition_of(
            &glob,
            crate::agents::ToolSteering::Terse,
            Some(&glob_override)
        )
        .description,
        "List files in this dependency package matching a glob; with no shell here, use it to discover entry points before reading them."
    );
    assert_eq!(
        definition_of(
            &glob,
            crate::agents::ToolSteering::Verbose,
            Some(&glob_override)
        )
        .description,
        glob.verbose_description().unwrap()
    );
}

// ── Issue #75 Stage 1: posture schema (additive, no behavior change) ──────

#[test]
fn agent_def_capabilities_parse_and_validate() {
    use super::AgentCapability;
    use std::collections::BTreeSet;

    let def = def_with_tools("custom", &["read", "bash"]);
    // An empty set = explicitly none.
    let mut def = def;
    def.capabilities = Some(BTreeSet::new());
    validate_invariants(&def).expect("empty capability set is valid");

    let mut caps = BTreeSet::new();
    caps.insert(AgentCapability::FollowupSeed);
    caps.insert(AgentCapability::SandboxEscalate);
    caps.insert(AgentCapability::ForkContext);
    caps.insert(AgentCapability::ScopedParallelWrite);
    def.capabilities = Some(caps);
    validate_invariants(&def).expect("all four capabilities are valid");

    // Wire names parse via serde.
    let yaml = "schemaVersion: 2\nagentId: test/cap\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: x\n    minContextTokens: 1\n    requiredCapabilities: [textGeneration]\n    locality: any\n    allowDefaultFallback: false\ncapabilities: [followupSeed, sandboxEscalate, forkContext, scopedParallelWrite]\ndescription: x\n";
    let parsed = parse_agent(yaml, "cap", "cap.md".into()).expect("capabilities parse");
    let resolved = parsed.capabilities.expect("capabilities present");
    assert!(resolved.contains(&AgentCapability::FollowupSeed));
    assert!(resolved.contains(&AgentCapability::ScopedParallelWrite));
}

#[test]
fn absent_capabilities_resolve_to_no_grants() {
    let def = def_with_tools("standard", &["read"]);
    let posture = PostureResolution::from_def(&def);

    assert!(posture.grants().is_empty());
    assert!(!posture.grants().contains(&AgentCapability::ForkContext));
}

#[test]
fn agent_def_load_and_model_override_warnings_are_advisory() {
    let text = "---\nschemaVersion: 2\nagentId: authored/local-worker\nexecutionKind: coding\nmodelSlots:\n  primary:\n    purpose: x\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: local\n    allowDefaultFallback: false\n    suggestedModels:\n      - recommendationId: local-small\n        upstreamIdentity: local/small-model\n        providerAliases:\n          - providerId: local\n            modelId: small-model\ncapabilities: [forkContext]\ndescription: local worker\n---\nbody\n";
    let def = parse_agent(text, "local-worker", "local-worker.md".into()).unwrap();
    let before = PostureResolution::from_def(&def).grants().clone();

    let load_warnings = def.load_warnings();
    assert_eq!(load_warnings.len(), 1);
    assert!(load_warnings[0].contains("local/small models"));
    assert!(def.model_override_warning("cloud", "large-model").is_some());
    assert!(def.model_override_warning("local", "small-model").is_none());
    assert_eq!(
        PostureResolution::from_def(&def).grants(),
        &before,
        "warnings must never mutate grants"
    );
}

#[test]
fn child_posture_intersection_never_widens_parent() {
    let mut parent = def_with_tools("parent", &["read"]);
    parent.capabilities = Some(BTreeSet::from([AgentCapability::FollowupSeed]));
    let mut child = def_with_tools("child", &["read"]);
    child.capabilities = Some(BTreeSet::from([
        AgentCapability::FollowupSeed,
        AgentCapability::SandboxEscalate,
    ]));

    let effective =
        PostureResolution::from_def(&child).intersect_parent(&PostureResolution::from_def(&parent));
    assert!(effective.grants().contains(&AgentCapability::FollowupSeed));
    assert!(
        !effective
            .grants()
            .contains(&AgentCapability::SandboxEscalate)
    );
}

#[test]
fn agent_def_tool_description_text_round_trips() {
    // A bare string parses as Text and serializes back as a bare string.
    let spec = ToolDescriptionSpec::Text("single canonical text".to_string());
    let yaml = serde_yaml::to_string(&spec).expect("serialize");
    assert_eq!(yaml.trim(), "single canonical text");

    let back: ToolDescriptionSpec = serde_yaml::from_str(&yaml).expect("deserialize");
    assert_eq!(back, spec);

    // to_override maps Text to the canonical terse/verbose representation.
    let ov = spec.to_override();
    assert_eq!(ov.text.as_deref(), Some("single canonical text"));
    assert_eq!(ov.verbose_text.as_deref(), Some("single canonical text"));

    let spec = ToolDescriptionSpec::WithVerbose {
        text: "canonical text".to_string(),
        verbose_text: Some("canonical text with warning prose".to_string()),
    };
    let yaml = serde_yaml::to_string(&spec).expect("serialize verbose form");
    assert!(yaml.contains("text: canonical text"), "{yaml}");
    assert!(yaml.contains("verboseText:"), "{yaml}");
    let back: ToolDescriptionSpec = serde_yaml::from_str(&yaml).expect("deserialize verbose form");
    assert_eq!(back, spec);
    let override_ = spec.to_override();
    assert_eq!(override_.text.as_deref(), Some("canonical text"));
    assert_eq!(
        override_.verbose_text.as_deref(),
        Some("canonical text with warning prose")
    );

    let canonical_only = ToolDescriptionSpec::WithVerbose {
        text: "canonical fallback".to_string(),
        verbose_text: None,
    }
    .to_override();
    assert_eq!(
        canonical_only.verbose_text.as_deref(),
        Some("canonical fallback")
    );
}

#[test]
fn agent_def_context_policy_bounds() {
    let mut def = def_with_tools("custom", &["read"]);
    // Valid bounds.
    def.context_policy = Some(crate::agents::ContextPolicy {
        auto_compact_pct: Some(10),
        inline_caps: Some(crate::agents::InlineCapsProfile::Conservative),
    });
    validate_invariants(&def).expect("10 is in range");

    def.context_policy = Some(crate::agents::ContextPolicy {
        auto_compact_pct: Some(95),
        inline_caps: Some(crate::agents::InlineCapsProfile::Large),
    });
    validate_invariants(&def).expect("95 is in range");

    // Out of range (below).
    def.context_policy = Some(crate::agents::ContextPolicy {
        auto_compact_pct: Some(9),
        inline_caps: None,
    });
    let err = validate_invariants(&def).unwrap_err().to_string();
    assert!(err.contains("autoCompactPct"), "{err}");
    assert!(err.contains("9"), "{err}");

    // Out of range (above).
    def.context_policy = Some(crate::agents::ContextPolicy {
        auto_compact_pct: Some(96),
        inline_caps: None,
    });
    let err = validate_invariants(&def).unwrap_err().to_string();
    assert!(err.contains("96"), "{err}");
}

#[test]
fn agent_def_digest_changes_iff_posture_fields_change() {
    // vnext_digest_bytes hashes the full canonical markdown, so the new
    // posture fields must survive canonical v2 serialization and affect the
    // digest iff they change.
    let mut base = parse_agent(
        &vnext_agent_document("A custom agent.", "body"),
        "custom",
        "custom.md".into(),
    )
    .expect("vNext base def");
    base.capabilities = None;
    base.tool_steering = None;
    base.context_policy = None;
    let digest_base = base.vnext_digest_bytes().expect("digest base");

    let mut with_caps = base.clone();
    let mut caps = std::collections::BTreeSet::new();
    caps.insert(crate::agents::AgentCapability::FollowupSeed);
    with_caps.capabilities = Some(caps);
    let digest_caps = with_caps.vnext_digest_bytes().expect("digest caps");
    assert_ne!(
        digest_base, digest_caps,
        "declaring capabilities must change the digest"
    );

    let mut with_steering = base.clone();
    with_steering.tool_steering = Some(crate::agents::ToolSteering::Verbose);
    let digest_steering = with_steering.vnext_digest_bytes().expect("digest steering");
    assert_ne!(
        digest_base, digest_steering,
        "declaring toolSteering must change the digest"
    );

    let mut with_policy = base.clone();
    with_policy.context_policy = Some(crate::agents::ContextPolicy {
        auto_compact_pct: Some(60),
        inline_caps: None,
    });
    let digest_policy = with_policy.vnext_digest_bytes().expect("digest policy");
    assert_ne!(
        digest_base, digest_policy,
        "declaring contextPolicy must change the digest"
    );

    // Reverting to None reproduces the base digest (stability).
    let mut reverted = with_caps.clone();
    reverted.capabilities = None;
    let digest_reverted = reverted.vnext_digest_bytes().expect("digest reverted");
    assert_eq!(
        digest_base, digest_reverted,
        "clearing the posture field reproduces the base digest"
    );

    let markdown = with_policy.to_markdown().expect("canonical markdown");
    let reparsed = parse_agent(&markdown, "custom", "custom.md".into())
        .expect("canonical vNext posture fields reparse");
    assert_eq!(reparsed.context_policy, with_policy.context_policy);
}

#[test]
fn single_file_vnext_digest_bytes_are_to_markdown_preimage() {
    // Existing installations must not flip to rebind_required: a single-file
    // def's digest preimage stays byte-identical to to_markdown().
    let def = parse_agent(
        &vnext_agent_document("Reviewer", "body"),
        "reviewer",
        "reviewer.md".into(),
    )
    .unwrap();
    assert!(def.package_files.is_none());
    assert_eq!(
        def.vnext_digest_bytes().unwrap(),
        def.to_markdown().unwrap().into_bytes()
    );
}

#[test]
fn package_digest_changes_iff_any_tree_file_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    let pkg = agents.join("pack");
    fs::create_dir_all(pkg.join("subagents")).unwrap();
    fs::write(
        pkg.join("agent.md"),
        vnext_agent_document("Package root", "ROOT BODY"),
    )
    .unwrap();
    fs::write(
        pkg.join("subagents").join("helper.md"),
        vnext_agent_document("Helper", "HELPER BODY"),
    )
    .unwrap();
    fs::write(pkg.join("mcp.json"), "{\"mcpServers\":{}}").unwrap();

    let def = trusted_resolve(tmp.path(), "pack")
        .unwrap()
        .expect("package resolves");
    assert!(def.is_package());
    assert_eq!(def.prompt, "ROOT BODY");
    assert_eq!(def.private_subagents.len(), 1);
    assert_eq!(
        def.private_subagents["helper"].prompt, "HELPER BODY",
        "private subagent body is loaded"
    );
    let digest = def.vnext_digest_bytes().unwrap();
    assert_ne!(
        digest,
        def.to_markdown().unwrap().into_bytes(),
        "package digest is whole-tree, not the root markdown alone"
    );

    fs::write(pkg.join("mcp.json"), "{\"mcpServers\":{\"x\":{}}}").unwrap();
    let after_mcp = trusted_resolve(tmp.path(), "pack")
        .unwrap()
        .expect("package resolves");
    assert_ne!(
        digest,
        after_mcp.vnext_digest_bytes().unwrap(),
        "mcp.json participates in the package digest"
    );

    fs::write(
        pkg.join("subagents").join("helper.md"),
        vnext_agent_document("Helper", "CHANGED HELPER"),
    )
    .unwrap();
    let after_child = trusted_resolve(tmp.path(), "pack")
        .unwrap()
        .expect("package resolves");
    assert_ne!(
        after_mcp.vnext_digest_bytes().unwrap(),
        after_child.vnext_digest_bytes().unwrap(),
        "private subagent contents participate in the package digest"
    );
}

#[test]
fn daemon_owned_package_threads_local_scope_through_root_and_children() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("pack");
    fs::create_dir_all(pkg.join("subagents")).unwrap();
    let root = vnext_agent_document("Local package", "ROOT").replace(
        "authored/reviewer",
        "local/00000000-0000-0000-0000-000000000041",
    );
    let child = vnext_agent_document("Local child", "CHILD").replace(
        "authored/reviewer",
        "local/00000000-0000-0000-0000-000000000042",
    );
    fs::write(pkg.join("agent.md"), root).unwrap();
    fs::write(pkg.join("subagents/helper.md"), child).unwrap();

    let loaded = load_owned_definition(&pkg, "pack", DefinitionScope::DaemonLocal)
        .expect("daemon-owned package accepts local identities throughout");
    assert_eq!(
        loaded.vnext.as_ref().unwrap().agent_id,
        "local/00000000-0000-0000-0000-000000000041"
    );
    assert_eq!(
        loaded.private_subagents["helper"]
            .vnext
            .as_ref()
            .unwrap()
            .agent_id,
        "local/00000000-0000-0000-0000-000000000042"
    );
    assert!(
        load_owned_definition(&pkg, "pack", DefinitionScope::Workspace).is_err(),
        "the same local package must remain invalid at a workspace boundary"
    );
}

#[test]
fn package_rejects_mode_primary_private_subagent() {
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    let pkg = agents.join("pack");
    fs::create_dir_all(pkg.join("subagents")).unwrap();
    fs::write(
        pkg.join("agent.md"),
        vnext_agent_document("Package root", "ROOT"),
    )
    .unwrap();
    fs::write(
        pkg.join("subagents").join("helper.md"),
        "---\ndescription: Helper\nmode: primary\n---\nbody\n",
    )
    .unwrap();
    let err = trusted_resolve(tmp.path(), "pack").unwrap_err().to_string();
    assert!(
        err.contains("mode") || err.contains("primary") || err.contains("schemaVersion"),
        "mode: primary under subagents/ is a validation error: {err}"
    );
}

#[test]
fn nearest_project_wins_over_outer_project_agent_def() {
    let tmp = tempfile::tempdir().unwrap();
    let outer = tmp.path();
    let inner = outer.join("inner");
    fs::create_dir_all(inner.join(".cockpit").join("agents")).unwrap();
    fs::create_dir_all(outer.join(".cockpit").join("agents")).unwrap();
    fs::write(
        outer.join(".cockpit").join("agents").join("rev.md"),
        vnext_agent_document("Outer", "OUTER BODY"),
    )
    .unwrap();
    fs::write(
        inner.join(".cockpit").join("agents").join("rev.md"),
        vnext_agent_document("Inner", "INNER BODY"),
    )
    .unwrap();

    let def = trusted_resolve(&inner, "rev")
        .unwrap()
        .expect("agent resolves");
    assert_eq!(
        def.prompt, "INNER BODY",
        "nearest project definition wins over an outer ancestor"
    );
    assert_eq!(def.description, "Inner");
}

#[test]
fn configured_agent_dirs_extend_across_config_layers() {
    let tmp = tempfile::tempdir().unwrap();
    let first = tmp.path().join("first");
    let second = tmp.path().join("second");
    fs::create_dir_all(first.join("agents-a")).unwrap();
    fs::create_dir_all(second.join("agents-b")).unwrap();
    fs::write(first.join("config.json"), r#"{"agent_dirs":["agents-a"]}"#).unwrap();
    fs::write(second.join("config.json"), r#"{"agent_dirs":["agents-b"]}"#).unwrap();

    let dirs =
        crate::config::trust::with_workspace_trust_policy(trusted_policy(tmp.path()), || {
            configured_agent_dirs_for_paths(&[
                first.join("config.json"),
                second.join("config.json"),
            ])
        });
    assert!(
        dirs.iter().any(|dir| dir.ends_with("agents-a")),
        "earlier layer agent_dirs must be kept: {dirs:?}"
    );
    assert!(
        dirs.iter().any(|dir| dir.ends_with("agents-b")),
        "later layer agent_dirs must extend rather than replace: {dirs:?}"
    );
}

#[test]
fn private_subagents_are_absent_from_inventory_listings() {
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    let pkg = agents.join("pack");
    fs::create_dir_all(pkg.join("subagents")).unwrap();
    fs::write(
        pkg.join("agent.md"),
        vnext_agent_document("Package root", "ROOT"),
    )
    .unwrap();
    fs::write(
        pkg.join("subagents").join("helper.md"),
        vnext_agent_document("Helper", "HELPER"),
    )
    .unwrap();
    let listings = trusted_list_all(tmp.path());
    assert!(
        listings.iter().any(|listing| listing.name == "pack"),
        "package root is listed"
    );
    assert!(
        listings.iter().all(|listing| listing.name != "helper"),
        "private subagent must not appear in GetAgentInventory/list_all"
    );
}

#[test]
fn package_grant_prefers_private_child_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let agents = project_agents_dir(tmp.path());
    let pkg = agents.join("pack");
    fs::create_dir_all(pkg.join("subagents")).unwrap();
    let mut root = vnext_agent_document("Package root", "ROOT");
    root = root.replace(
        "allowDefaultFallback: false\n---",
        "allowDefaultFallback: false\ndelegation:\n  allowedChildren: [{kind: portable_ref, ref: helper}]\n  maxDescendantDepth: 1\n  maxConcurrentChildren: 1\n  targets: [same_root]\n  defaultChild: helper\n---",
    );
    fs::write(pkg.join("agent.md"), root).unwrap();
    fs::write(
        pkg.join("subagents").join("helper.md"),
        vnext_agent_document("Helper", "HELPER"),
    )
    .unwrap();
    let def = trusted_resolve(tmp.path(), "pack")
        .unwrap()
        .expect("package resolves");
    let host = crate::agents::VnextHostPolicy::for_session_config(
        &crate::config::extended::ExtendedConfig::default(),
    );
    let grant = def.resolve_vnext_grant(&host).expect("grant resolves");
    assert!(
        grant
            .delegation
            .as_ref()
            .unwrap()
            .package_children
            .contains_key("helper")
    );
    assert_eq!(
        grant.delegation.as_ref().unwrap().default_child.as_deref(),
        Some("helper")
    );
}
