//! Compact read-only diagnostics snapshot for CLI and TUI surfaces.

use std::path::{Path, PathBuf};

use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsInput {
    pub cwd: PathBuf,
    pub session_id: Option<uuid::Uuid>,
    pub session_short_id: Option<String>,
    pub active_agent: String,
    pub active_model: Option<(String, String)>,
    pub sandbox_enabled: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticsSnapshot {
    pub session: String,
    pub active_agent: String,
    pub active_model: String,
    pub cwd: String,
    pub project_root: String,
    pub workspace_trust: String,
    pub sandbox: String,
    pub approval_mode: String,
    pub providers: Vec<String>,
    pub harnesses: Vec<String>,
    pub delegation: Vec<String>,
}

pub fn cli_snapshot(path: Option<&Path>, no_sandbox: bool) -> Result<DiagnosticsSnapshot> {
    let launch = crate::welcome::load(path, false);
    build_snapshot(DiagnosticsInput {
        cwd: launch.cwd,
        session_id: None,
        session_short_id: None,
        active_agent: launch.agent_name,
        active_model: launch.active_model,
        sandbox_enabled: Some(!no_sandbox),
    })
}

pub fn tui_snapshot(input: DiagnosticsInput) -> Result<DiagnosticsSnapshot> {
    build_snapshot(input)
}

pub fn render(snapshot: &DiagnosticsSnapshot) -> String {
    let mut out = String::new();
    out.push_str("Cockpit diagnostics\n");
    out.push_str(&format!("session: {}\n", snapshot.session));
    out.push_str(&format!("agent: {}\n", snapshot.active_agent));
    out.push_str(&format!("model: {}\n", snapshot.active_model));
    out.push_str(&format!("cwd: {}\n", snapshot.cwd));
    out.push_str(&format!("project root: {}\n", snapshot.project_root));
    out.push_str(&format!("workspace trust: {}\n", snapshot.workspace_trust));
    out.push_str(&format!("sandbox: {}\n", snapshot.sandbox));
    out.push_str(&format!("approval: {}\n", snapshot.approval_mode));
    push_section(&mut out, "providers", &snapshot.providers);
    push_section(&mut out, "harnesses", &snapshot.harnesses);
    push_section(&mut out, "delegation", &snapshot.delegation);
    out
}

fn build_snapshot(input: DiagnosticsInput) -> Result<DiagnosticsSnapshot> {
    let trust_root = crate::config::trust::resolve_trust_root(&input.cwd)?;
    let providers = crate::config::providers::ConfigDoc::load_effective(&input.cwd);
    let extended = crate::config::extended::load_for_cwd(&input.cwd);
    let harnesses = crate::config::extended::resolve_harnesses(&input.cwd);
    let trust_mode = workspace_trust_mode(&input.cwd)?;
    let trust_resolved = trust_mode != "unresolved";

    Ok(DiagnosticsSnapshot {
        session: session_label(input.session_id, input.session_short_id.as_deref()),
        active_agent: input.active_agent.clone(),
        active_model: input
            .active_model
            .as_ref()
            .map(|(p, m)| format!("{p}/{m}"))
            .unwrap_or_else(|| "none".to_string()),
        cwd: input.cwd.display().to_string(),
        project_root: trust_root.root.display().to_string(),
        workspace_trust: format!(
            "{trust_mode} ({}: {})",
            trust_root.kind.as_str(),
            trust_root.root.display()
        ),
        sandbox: input
            .sandbox_enabled
            .map(|enabled| if enabled { "on" } else { "off" }.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        approval_mode: extended.default_approval_mode.as_str().to_string(),
        providers: provider_lines(&providers, extended.trusted_only),
        harnesses: harness_lines(&harnesses, trust_resolved),
        delegation: delegation_lines(
            &input.active_agent,
            &input.cwd,
            !harnesses.is_empty(),
            &extended,
        ),
    })
}

fn push_section(out: &mut String, label: &str, lines: &[String]) {
    out.push_str(label);
    out.push_str(":\n");
    if lines.is_empty() {
        out.push_str("  none\n");
    } else {
        for line in lines {
            out.push_str("  - ");
            out.push_str(line);
            out.push('\n');
        }
    }
}

fn session_label(id: Option<uuid::Uuid>, short_id: Option<&str>) -> String {
    match (id, short_id.filter(|s| !s.is_empty())) {
        (Some(id), Some(short)) => format!("{short} ({id})"),
        (Some(id), None) => id.to_string(),
        (None, Some(short)) => short.to_string(),
        (None, None) => "none".to_string(),
    }
}

fn workspace_trust_mode(cwd: &Path) -> Result<String> {
    let db = crate::db::Db::open_default()?;
    let mode = db
        .workspace_trust_for_path(cwd)?
        .map(|decision| decision.mode.as_str().to_string())
        .unwrap_or_else(|| "unresolved".to_string());
    Ok(mode)
}

fn provider_lines(
    cfg: &crate::config::providers::ProvidersConfig,
    trusted_only: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    for (id, provider) in &cfg.providers {
        let fetch = provider
            .last_model_fetch
            .as_ref()
            .map(|status| model_fetch_status_label(status.status))
            .unwrap_or("not fetched");
        let model_count = provider.models.len();
        let trusted_count = provider
            .models
            .iter()
            .filter(|model| cfg.resolve_trust(id, &model.id).is_trusted())
            .count();
        let subagent_count = provider
            .models
            .iter()
            .filter(|model| cfg.resolve_subagent_invokable(id, &model.id))
            .count();
        let hidden_count = model_count.saturating_sub(subagent_count);
        let ranked_count = provider
            .models
            .iter()
            .filter(|model| {
                cfg.resolve_quality_rank(id, &model.id) != 0
                    || cfg.resolve_cost_rank(id, &model.id) != 0
            })
            .count();
        let mut notes = vec![
            format!("trusted {trusted_count}/{model_count}"),
            format!("subagent-invokable {subagent_count}/{model_count}"),
            format!("ranked {ranked_count}/{model_count}"),
        ];
        if hidden_count > 0 {
            notes.push(format!("{hidden_count} hidden from subagent routing"));
        }
        if trusted_only && model_count > 0 && trusted_count == 0 {
            notes.push("trusted-only: no eligible trusted models".to_string());
        }
        out.push(format!(
            "{id}: {model_count} model(s), fetch {fetch}, {}",
            notes.join(", ")
        ));
    }
    out
}

fn model_fetch_status_label(
    status: crate::config::providers::ModelFetchStatusKind,
) -> &'static str {
    match status {
        crate::config::providers::ModelFetchStatusKind::Live => "live",
        crate::config::providers::ModelFetchStatusKind::FailedKeptExisting => {
            "failed_kept_existing"
        }
        crate::config::providers::ModelFetchStatusKind::Fallback => "fallback",
        crate::config::providers::ModelFetchStatusKind::Unsupported => "unsupported",
        crate::config::providers::ModelFetchStatusKind::AuthFailed => "auth_failed",
    }
}

fn harness_lines(
    harnesses: &std::collections::HashMap<String, crate::config::extended::HarnessConfig>,
    trust_resolved: bool,
) -> Vec<String> {
    let mut ids: Vec<&String> = harnesses.keys().collect();
    ids.sort();
    ids.into_iter()
        .map(|id| {
            let harness = &harnesses[id];
            let path = if !trust_resolved {
                "trust-blocked".to_string()
            } else if command_on_path(&harness.command) {
                "on PATH, auth not probed".to_string()
            } else {
                "NOT on PATH".to_string()
            };
            let default = harness.default_model.as_deref().unwrap_or("none");
            format!(
                "{id}: {path}, command `{}`, default {default}, {} model(s)",
                harness.command,
                harness.models.len()
            )
        })
        .collect()
}

fn delegation_lines(
    active_agent: &str,
    cwd: &Path,
    harness_configured: bool,
    extended: &crate::config::extended::ExtendedConfig,
) -> Vec<String> {
    vec![
        format!(
            "task: {}",
            availability(agent_has_tool(cwd, active_agent, "task"))
        ),
        format!(
            "external harness tools: {}",
            availability(
                harness_configured
                    && (agent_has_tool(cwd, active_agent, "harness_invoke")
                        || matches!(active_agent, "Build" | "Plan"))
            )
        ),
        format!(
            "trusted-only mode: {}",
            if extended.trusted_only { "on" } else { "off" }
        ),
        format!(
            "deepthink: {} (tool-free reasoning-only)",
            if extended.deepthink.enabled {
                "enabled"
            } else {
                "disabled"
            }
        ),
        format!(
            "task recursion: {}, default child budget {}, batch max {}",
            if extended.delegation.recursion_enabled {
                "enabled"
            } else {
                "disabled"
            },
            extended.delegation.default_recursion_depth,
            extended.delegation.max_parallel
        ),
        format!(
            "swarm recursion: max depth {}, max concurrency {}",
            extended.swarm.max_depth, extended.swarm.max_concurrency
        ),
    ]
}

fn availability(ok: bool) -> &'static str {
    if ok { "available" } else { "unavailable" }
}

fn agent_has_tool(cwd: &Path, agent: &str, tool: &str) -> bool {
    match crate::agents::resolve(cwd, agent) {
        Ok(Some(def)) => def
            .tools
            .as_ref()
            .is_some_and(|tools| tools.iter().any(|t| t == tool)),
        _ => false,
    }
}

fn command_on_path(command: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{command}.exe"), command.to_string()]
    } else {
        vec![command.to_string()]
    };
    std::env::split_paths(&paths).any(|dir| names.iter().any(|name| dir.join(name).is_file()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_input(cwd: &Path) -> DiagnosticsInput {
        DiagnosticsInput {
            cwd: cwd.to_path_buf(),
            session_id: Some(uuid::Uuid::nil()),
            session_short_id: Some("abc123".to_string()),
            active_agent: "Build".to_string(),
            active_model: Some(("p".to_string(), "m".to_string())),
            sandbox_enabled: Some(true),
        }
    }

    #[test]
    fn cli_and_tui_paths_share_snapshot_builder() {
        let tmp = tempfile::tempdir().unwrap();
        let input = base_input(tmp.path());

        let tui = tui_snapshot(input.clone()).unwrap();
        let direct = build_snapshot(input).unwrap();

        assert_eq!(tui, direct);
        assert!(render(&tui).contains("Cockpit diagnostics"));
    }

    #[test]
    fn unresolved_trust_marks_harness_probe_blocked() {
        crate::config::trust::clear_runtime_policy_for_tests();
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{"harnesses":{"codex-oauth":{"command":"definitely-missing-codex","models":["codex"]}}}"#,
        )
        .unwrap();

        let snapshot = build_snapshot(base_input(tmp.path())).unwrap();

        assert!(snapshot.workspace_trust.contains("unresolved"));
        assert!(snapshot.harnesses[0].contains("trust-blocked"));
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    #[test]
    fn diagnostics_surface_model_policy_and_delegation_settings() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        let config_path = cockpit.join("config.json");
        std::fs::write(
            &config_path,
            r#"{
                "trustedOnly": true,
                "deepthink": { "enabled": true },
                "delegation": {
                    "maxParallel": 3,
                    "recursionEnabled": true,
                    "defaultRecursionDepth": 2
                },
                "swarm": { "maxDepth": 4, "maxConcurrency": 5 }
            }"#,
        )
        .unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "mixed").unwrap();
        std::fs::write(
            provider_path,
            r#"{
                "url": "https://mixed.example/v1",
                "trust": "untrusted",
                "models": [
                    { "id": "parent-untrusted", "subagent_invokable": true },
                    { "id": "child-trusted", "trust": "trusted", "subagent_invokable": true, "quality_rank": 9, "cost_rank": 3 },
                    { "id": "hidden-trusted", "trust": "trusted", "subagent_invokable": false }
                ]
            }"#,
        )
        .unwrap();

        let snapshot = build_snapshot(base_input(tmp.path())).unwrap();
        let rendered = render(&snapshot);

        assert!(
            rendered.contains(
                "mixed: 3 model(s), fetch not fetched, trusted 2/3, subagent-invokable 2/3"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains("1 hidden from subagent routing"),
            "{rendered}"
        );
        assert!(rendered.contains("trusted-only mode: on"), "{rendered}");
        assert!(
            rendered.contains("deepthink: enabled (tool-free reasoning-only)"),
            "{rendered}"
        );
        assert!(
            rendered.contains("task recursion: enabled, default child budget 2, batch max 3"),
            "{rendered}"
        );
        assert!(
            rendered.contains("swarm recursion: max depth 4, max concurrency 5"),
            "{rendered}"
        );
    }
}
