//! Compact read-only diagnostics snapshot for CLI and TUI surfaces.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt as _;

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
    pub container_runtime: String,
    pub container_harness: String,
    pub container_available: String,
    pub approval_mode: String,
    pub providers: Vec<String>,
    pub git: Vec<String>,
    pub network: Vec<String>,
    pub harnesses: Vec<String>,
    pub delegation: Vec<String>,
    pub has_failures: bool,
}

pub async fn cli_snapshot(
    path: Option<&Path>,
    no_sandbox: bool,
    offline: bool,
) -> Result<DiagnosticsSnapshot> {
    let launch = crate::welcome::load(path, false);
    let mut snapshot = build_snapshot(DiagnosticsInput {
        cwd: launch.cwd,
        session_id: None,
        session_short_id: None,
        active_agent: launch.agent_name,
        active_model: launch.active_model,
        sandbox_enabled: Some(!no_sandbox),
    })?;
    let providers = crate::secret_ref::load_effective(Path::new(&snapshot.cwd));
    let (network, network_failed) = provider_network_lines(&providers, offline).await;
    snapshot.network = network;
    snapshot.has_failures |= network_failed;
    Ok(snapshot)
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
    push_section(
        &mut out,
        "container",
        &[
            format!("runtime: {}", snapshot.container_runtime),
            format!("harness: {}", snapshot.container_harness),
            format!("available: {}", snapshot.container_available),
        ],
    );
    out.push_str(&format!("approval: {}\n", snapshot.approval_mode));
    push_section(&mut out, "providers", &snapshot.providers);
    push_section(&mut out, "network", &snapshot.network);
    push_section(&mut out, "git", &snapshot.git);
    push_section(&mut out, "harnesses", &snapshot.harnesses);
    push_section(&mut out, "delegation", &snapshot.delegation);
    out
}

fn build_snapshot(input: DiagnosticsInput) -> Result<DiagnosticsSnapshot> {
    let trust_root = crate::config::trust::resolve_trust_root(&input.cwd)?;
    let providers = crate::secret_ref::load_effective(&input.cwd);
    let extended = crate::config::extended::load_for_cwd(&input.cwd);
    let harnesses = crate::config::extended::resolve_harnesses(&input.cwd);
    let trust_mode = workspace_trust_mode(&input.cwd);
    let trust_resolved = trust_mode != "unresolved";
    let container = crate::container::availability_snapshot();
    let container_reason = container
        .reason
        .map(|reason| reason.as_str())
        .unwrap_or("none");

    let delegation_enabled = delegation_enabled_for_coverage(&providers, &extended, &input);
    let (providers, provider_failures) = provider_lines(&providers, &extended, delegation_enabled);
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
        container_runtime: container
            .runtime
            .map(|runtime| runtime.as_str().to_string())
            .unwrap_or_else(|| "none".to_string()),
        container_harness: container.harness_in_container.to_string(),
        container_available: if container.available {
            "true".to_string()
        } else {
            format!("false ({container_reason})")
        },
        approval_mode: extended.default_approval_mode.as_str().to_string(),
        providers,
        git: git_lines(&input.cwd),
        network: Vec::new(),
        harnesses: harness_lines(&harnesses, trust_resolved),
        delegation: delegation_lines(
            &input.active_agent,
            &input.cwd,
            !harnesses.is_empty(),
            &extended,
        ),
        has_failures: provider_failures,
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

fn workspace_trust_mode(cwd: &Path) -> String {
    let Ok(db) = crate::db::Db::open_default() else {
        return "unresolved".to_string();
    };
    let Ok(root) = crate::config::trust::resolve_trust_root(cwd) else {
        return "unresolved".to_string();
    };
    db.workspace_trust_by_root(&root.root)
        .ok()
        .flatten()
        .map(|decision| decision.mode.as_str().to_string())
        .unwrap_or_else(|| "unresolved".to_string())
}

fn provider_lines(
    cfg: &crate::config::providers::ProvidersConfig,
    extended: &crate::config::extended::ExtendedConfig,
    delegation_enabled: bool,
) -> (Vec<String>, bool) {
    let trusted_only = extended.trusted_only;
    let mut out = Vec::new();
    let mut failed = false;
    match cfg.resolve_embedding_model(extended) {
        Ok(resolved) => out.push(format!(
            "embedding_model: resolved {}/{}{}",
            resolved.provider,
            resolved.model,
            resolved
                .embedding_dimensions
                .map(|dims| format!(" ({dims} dims)"))
                .unwrap_or_default()
        )),
        Err(err) => out.push(format!("embedding_model: unresolved ({err})")),
    }
    if cfg.providers.is_empty() {
        out.push("no providers configured; run: cockpit provider add".to_string());
        return (out, true);
    }
    let mut total_invokable = 0usize;
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
        let eligible_subagent_count = provider
            .models
            .iter()
            .filter(|model| {
                cfg.resolve_subagent_invokable(id, &model.id)
                    && (!trusted_only || cfg.resolve_trust(id, &model.id).is_trusted())
            })
            .count();
        total_invokable += eligible_subagent_count;
        let can_delegate_count = provider
            .models
            .iter()
            .filter(|model| cfg.resolve_can_delegate(id, &model.id))
            .count();
        let mut computer_disabled = 0usize;
        let mut computer_ask = 0usize;
        let mut computer_yolo = 0usize;
        let mut computer_vision_models = 0usize;
        for model in &provider.models {
            let tier =
                cfg.resolve_computer_use_effective(id, &model.id, extended.computer_use, None);
            match tier {
                crate::config::extended::ComputerUseMode::Disabled => {
                    computer_disabled += 1;
                }
                crate::config::extended::ComputerUseMode::Ask => {
                    computer_ask += 1;
                }
                crate::config::extended::ComputerUseMode::Yolo => {
                    computer_yolo += 1;
                }
            }
            let caps = cfg.resolve_capabilities(id, &model.id);
            if tier != crate::config::extended::ComputerUseMode::Disabled
                && caps.images == Some(true)
                && caps
                    .computer_use
                    .as_ref()
                    .is_some_and(|c| c.contract.is_some())
            {
                computer_vision_models += 1;
            }
        }
        let embedding_count = provider
            .models
            .iter()
            .filter(|model| cfg.resolve_capabilities(id, &model.id).embeddings == Some(true))
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
            format!("can-delegate {can_delegate_count}/{model_count}"),
            format!(
                "computer-use disabled/ask/yolo {computer_disabled}/{computer_ask}/{computer_yolo}"
            ),
            format!("computer-vision {computer_vision_models}/{model_count}"),
            format!("embedding-capable {embedding_count}/{model_count}"),
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
        let (credential, credential_failed) = credential_line(id, provider);
        failed |= credential_failed;
        out.push(credential);
    }
    match (delegation_enabled, total_invokable) {
        (true, 0) => {
            out.push(
                "subagent failover coverage: FAILED; delegation is available but no eligible subagent-invokable models are configured"
                    .to_string(),
            );
            failed = true;
        }
        (false, 0) => out.push(
            "subagent failover coverage: informational; delegation is unavailable and no subagent-invokable models are configured"
                .to_string(),
        ),
        (true, 1) => out.push(
            "subagent failover coverage: WARNING; exactly one eligible subagent-invokable model is configured, so delegation has no model failover"
                .to_string(),
        ),
        _ => out.push(format!(
            "subagent failover coverage: {total_invokable} eligible subagent-invokable models"
        )),
    }
    out.push("subagent failover reachability: not probed in this snapshot; run online `cockpit doctor` network checks for provider reachability".to_string());
    (out, failed)
}

fn delegation_enabled_for_coverage(
    cfg: &crate::config::providers::ProvidersConfig,
    _extended: &crate::config::extended::ExtendedConfig,
    input: &DiagnosticsInput,
) -> bool {
    let active_can_delegate = input
        .active_model
        .as_ref()
        .map(|(provider, model)| cfg.resolve_can_delegate(provider, model))
        .unwrap_or(true);
    active_can_delegate && agent_has_tool(&input.cwd, &input.active_agent, "task")
}

fn credential_line(
    provider_id: &str,
    provider: &crate::config::providers::ProviderEntry,
) -> (String, bool) {
    let store = crate::credentials::CredentialStore::open_default_readonly().ok();
    credential_line_with_sources(
        provider_id,
        provider,
        |name| std::env::var(name).ok(),
        |name| {
            store
                .as_ref()
                .and_then(|store| store.named_secret(name))
                .map(str::to_string)
        },
        |credential_ref| {
            store
                .as_ref()
                .and_then(|store| store.get(credential_ref))
                .is_some()
        },
    )
}

fn credential_line_with_sources<E, S, C>(
    provider_id: &str,
    provider: &crate::config::providers::ProviderEntry,
    env_lookup: E,
    secret_lookup: S,
    credential_present: C,
) -> (String, bool)
where
    E: Fn(&str) -> Option<String>,
    S: Fn(&str) -> Option<String>,
    C: Fn(&str) -> bool,
{
    if provider.auth == Some(crate::config::providers::AuthKind::None) {
        return (format!("{provider_id} credentials: not required"), false);
    }
    if let Some(credential_ref) = provider.credential_ref.as_deref() {
        if credential_present(credential_ref) {
            return (
                format!("{provider_id} credentials: ok (credential {credential_ref})"),
                false,
            );
        }
        return (
            format!(
                "{provider_id} credentials: MISSING — credential `{credential_ref}` not found; run: cockpit provider add {}",
                provider
                    .effective_template(provider_id)
                    .unwrap_or(provider_id)
            ),
            true,
        );
    }

    if provider.headers.is_empty() {
        return (
            format!(
                "{provider_id} credentials: none configured; run: cockpit provider add {provider_id}"
            ),
            true,
        );
    }

    let mut refs = Vec::new();
    let mut missing = Vec::new();
    let mut has_literal = false;
    for header in &provider.headers {
        let resolved = crate::envref::resolve_with_sources(
            &header.value,
            |name| env_lookup(name).filter(|value| !value.trim().is_empty()),
            |name| secret_lookup(name).filter(|value| !value.trim().is_empty()),
        );
        if resolved.referenced.is_empty() {
            has_literal = true;
        }
        refs.extend(resolved.referenced);
        missing.extend(resolved.missing);
        missing.extend(resolved.errors);
    }
    refs.sort();
    refs.dedup();
    missing.sort();
    missing.dedup();

    if !missing.is_empty() {
        let rendered = missing
            .iter()
            .map(|name| {
                if let Some(secret) = name.strip_prefix("secret:") {
                    format!("$secret:{secret} not found")
                } else if name.starts_with("invalid ") {
                    name.clone()
                } else {
                    format!("${name} not set")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        return (
            format!(
                "{provider_id} credentials: MISSING — {rendered}; run: cockpit provider add {}",
                provider
                    .effective_template(provider_id)
                    .unwrap_or(provider_id)
            ),
            true,
        );
    }

    let source = if refs.is_empty() {
        if has_literal {
            "literal header".to_string()
        } else {
            "configured headers".to_string()
        }
    } else {
        refs.iter()
            .map(|name| {
                if let Some(secret) = name.strip_prefix("secret:") {
                    format!("secret {secret}")
                } else {
                    format!("env {name}")
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    (format!("{provider_id} credentials: ok ({source})"), false)
}

async fn provider_network_lines(
    cfg: &crate::config::providers::ProvidersConfig,
    offline: bool,
) -> (Vec<String>, bool) {
    if offline {
        return (
            vec!["network checks: skipped (--offline)".to_string()],
            false,
        );
    }
    if cfg.providers.is_empty() {
        return (
            vec!["network checks: no providers configured; run: cockpit provider add".to_string()],
            true,
        );
    }
    let mut results = futures::stream::iter(cfg.providers.iter().enumerate().map(
        |(idx, (id, provider))| {
            let has_invokable_models = provider
                .models
                .iter()
                .any(|model| cfg.resolve_subagent_invokable(id, &model.id));
            async move {
        let Some(template_id) = provider.effective_template(id) else {
            return (
                idx,
                format!("{id}: skipped (custom provider has no built-in auth check)"),
                false,
            );
        };
        let Some(template) = crate::providers::template_by_id(template_id) else {
            return (
                idx,
                format!("{id}: skipped (unknown provider template {template_id})"),
                false,
            );
        };
        let (line, failed) = match crate::providers::auth_check::check_provider_auth(
            id,
            provider,
            template,
            Duration::from_secs(5),
        )
        .await
        {
            Ok(_) => (format!("{id}: reachable · credentials verified"), false),
            Err(crate::providers::auth_check::AuthCheckError::CredentialsRejected(error)) => (
                format!(
                    "{id}: reachable · credentials REJECTED ({}) — run: cockpit provider add {template_id}",
                    one_line(&error)
            ),
            true,
            ),
            Err(crate::providers::auth_check::AuthCheckError::Network(error))
                if has_invokable_models =>
            {
                (
                    format!(
                        "{id}: WARNING unreachable for subagent failover ({}) — check network/proxy; run: cockpit provider add {template_id}",
                        one_line(&error)
                    ),
                    false,
                )
            }
            Err(crate::providers::auth_check::AuthCheckError::Network(error)) => (
                format!(
                    "{id}: UNREACHABLE ({}) — check network/proxy; run: cockpit provider add {template_id}",
                    one_line(&error)
                ),
                true,
            ),
            Err(crate::providers::auth_check::AuthCheckError::Other(error)) => (
                format!(
                    "{id}: check failed ({}) — run: cockpit provider add {template_id}",
                    one_line(&error)
                ),
                true,
            ),
        };
        (idx, line, failed)
            }
        },
    ))
    .buffer_unordered(4)
    .collect::<Vec<_>>()
    .await;
    results.sort_by_key(|(idx, _, _)| *idx);
    let failed = results.iter().any(|(_, _, failed)| *failed);
    let out = results
        .into_iter()
        .map(|(_, line, _)| line)
        .collect::<Vec<_>>();
    (out, failed)
}

fn one_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn git_lines(cwd: &Path) -> Vec<String> {
    let Some(version) = command_output(Command::new("git").arg("--version")) else {
        return vec!["git: not found (informational)".to_string()];
    };
    let mut out = vec![format!("git: {}", version.trim())];
    let Some(is_repo) = command_output(
        Command::new("git")
            .arg("-C")
            .arg(cwd)
            .arg("rev-parse")
            .arg("--is-inside-work-tree"),
    ) else {
        out.push("repo: no (informational)".to_string());
        return out;
    };
    if is_repo.trim() != "true" {
        out.push("repo: no (informational)".to_string());
        return out;
    }
    out.push("repo: yes".to_string());
    let branch = command_output(
        Command::new("git")
            .arg("-C")
            .arg(cwd)
            .arg("branch")
            .arg("--show-current"),
    )
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
    .unwrap_or_else(|| "detached".to_string());
    let dirty = command_output(
        Command::new("git")
            .arg("-C")
            .arg(cwd)
            .arg("status")
            .arg("--short"),
    )
    .map(|value| value.lines().count())
    .unwrap_or(0);
    out.push(format!("branch: {branch}"));
    out.push(format!("dirty: {dirty} changed path(s)"));
    out
}

fn command_output(command: &mut Command) -> Option<String> {
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).to_string())
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
    use crate::config::providers::{AuthKind, HeaderSpec, ProviderEntry, ProvidersConfig};

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

    fn provider_with_header(value: &str) -> ProviderEntry {
        ProviderEntry {
            url: "https://example.test/v1".to_string(),
            auth: Some(AuthKind::ApiKey),
            headers: vec![HeaderSpec {
                name: "Authorization".to_string(),
                value: value.to_string(),
            }],
            ..ProviderEntry::default()
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

    #[test]
    fn can_delegate_doctor_reports_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        let config_path = cockpit.join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "mixed").unwrap();
        std::fs::write(
            provider_path,
            r#"{
                "url": "https://mixed.example/v1",
                "can_delegate": false,
                "models": [
                    { "id": "provider-off" },
                    { "id": "model-on", "can_delegate": true },
                    { "id": "model-off", "can_delegate": false }
                ]
            }"#,
        )
        .unwrap();

        let snapshot = build_snapshot(base_input(tmp.path())).unwrap();
        let rendered = render(&snapshot);

        assert!(rendered.contains("can-delegate 1/3"), "{rendered}");
    }

    fn coverage_cfg(model: crate::config::providers::ModelEntry) -> ProvidersConfig {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".to_string(),
            ProviderEntry {
                url: "https://p.example/v1".to_string(),
                auth: Some(AuthKind::None),
                models: vec![model],
                ..ProviderEntry::default()
            },
        );
        cfg
    }

    #[test]
    fn doctor_fails_when_delegation_enabled_and_no_invokable_models() {
        let cfg = coverage_cfg(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            can_delegate: Some(true),
            ..Default::default()
        });
        let (lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            true,
        );
        let rendered = lines.join("\n");
        assert!(failed, "{rendered}");
        assert!(
            rendered.contains("subagent failover coverage: FAILED"),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_does_not_fail_when_delegation_disabled_and_no_invokable_models() {
        let cfg = coverage_cfg(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            can_delegate: Some(false),
            ..Default::default()
        });
        let (lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            false,
        );
        let rendered = lines.join("\n");
        assert!(!failed, "{rendered}");
        assert!(
            rendered.contains("subagent failover coverage: informational"),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_warns_but_does_not_fail_with_single_invokable_model() {
        let cfg = coverage_cfg(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            can_delegate: Some(true),
            subagent_invokable: Some(true),
            ..Default::default()
        });
        let (lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            true,
        );
        let rendered = lines.join("\n");
        assert!(!failed, "{rendered}");
        assert!(
            rendered.contains("subagent failover coverage: WARNING"),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_offline_skips_invokable_reachability_probe() {
        let mut cfg = coverage_cfg(crate::config::providers::ModelEntry {
            id: "m".to_string(),
            can_delegate: Some(true),
            subagent_invokable: Some(true),
            ..Default::default()
        });
        cfg.providers
            .get_mut("p")
            .unwrap()
            .models
            .push(crate::config::providers::ModelEntry {
                id: "n".to_string(),
                subagent_invokable: Some(true),
                ..Default::default()
            });
        let (lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            true,
        );
        let rendered = lines.join("\n");
        assert!(
            rendered.contains("subagent failover reachability: not probed"),
            "{rendered}"
        );
        assert!(!failed, "{rendered}");
    }

    #[test]
    fn doctor_reports_computer_use() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        let config_path = cockpit.join("config.json");
        std::fs::write(&config_path, "{}").unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "mixed").unwrap();
        std::fs::write(
            provider_path,
            r#"{
                "url": "https://mixed.example/v1",
                "computer_use": "yolo",
                "models": [
                    {
                        "id": "provider-yolo",
                        "capabilities": { "images": false }
                    },
                    {
                        "id": "model-ask",
                        "computer_use": "ask",
                        "capabilities": {
                            "images": true,
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    },
                    {
                        "id": "model-disabled",
                        "computer_use": "disabled",
                        "capabilities": {
                            "images": true,
                            "computer_use": { "contract": "open_ai_responses" }
                        }
                    }
                ]
            }"#,
        )
        .unwrap();

        let snapshot = build_snapshot(base_input(tmp.path())).unwrap();
        let rendered = render(&snapshot);

        assert!(
            rendered.contains("computer-use disabled/ask/yolo 1/1/1"),
            "{rendered}"
        );
        assert!(rendered.contains("computer-vision 1/3"), "{rendered}");
    }

    #[test]
    fn doctor_renders_container_block() {
        let tmp = tempfile::tempdir().unwrap();
        let rendered = render(&build_snapshot(base_input(tmp.path())).unwrap());

        assert!(rendered.contains("container:"), "{rendered}");
        assert!(rendered.contains("runtime:"), "{rendered}");
        assert!(rendered.contains("harness:"), "{rendered}");
        assert!(rendered.contains("available:"), "{rendered}");
    }

    #[test]
    fn doctor_credential_resolvability_states() {
        let cases = [
            (
                "env-ok",
                provider_with_header("Bearer $COCKPIT_DOCTOR_PRESENT_KEY"),
            ),
            (
                "env-missing",
                provider_with_header("Bearer $COCKPIT_DOCTOR_MISSING_KEY"),
            ),
            (
                "secret-ok",
                provider_with_header("Bearer $secret:doctor-present"),
            ),
            (
                "secret-missing",
                provider_with_header("Bearer $secret:doctor-missing"),
            ),
        ];
        let mut lines = Vec::new();
        let mut failed = false;
        for (id, provider) in cases {
            let (line, line_failed) = credential_line_with_sources(
                id,
                &provider,
                |name| {
                    (name == "COCKPIT_DOCTOR_PRESENT_KEY").then(|| "sk-present-secret".to_string())
                },
                |name| (name == "doctor-present").then(|| "sk-named-secret-value".to_string()),
                |_| false,
            );
            lines.push(line);
            failed |= line_failed;
        }
        let rendered = lines.join("\n");

        assert!(failed);
        assert!(
            rendered.contains("env-ok credentials: ok (env COCKPIT_DOCTOR_PRESENT_KEY)"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "env-missing credentials: MISSING — $COCKPIT_DOCTOR_MISSING_KEY not set; run:"
            ),
            "{rendered}"
        );
        assert!(
            rendered.contains("secret-ok credentials: ok (secret doctor-present)"),
            "{rendered}"
        );
        assert!(
            rendered.contains(
                "secret-missing credentials: MISSING — $secret:doctor-missing not found; run:"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains("sk-present-secret"), "{rendered}");
        assert!(!rendered.contains("sk-named-secret-value"), "{rendered}");
    }

    async fn one_shot_server(status: &'static str, body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut buf = vec![0; 4096];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        format!("http://{addr}/v1")
    }

    fn network_cfg(base_url: String) -> ProvidersConfig {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "zai-test".to_string(),
            ProviderEntry {
                url: base_url,
                template: Some("z-ai".to_string()),
                auth: Some(AuthKind::ApiKey),
                headers: vec![HeaderSpec {
                    name: "Authorization".to_string(),
                    value: "Bearer literal-test-token".to_string(),
                }],
                ..ProviderEntry::default()
            },
        );
        cfg
    }

    fn network_cfg_with_invokable(base_url: String) -> ProvidersConfig {
        let mut cfg = network_cfg(base_url);
        cfg.providers.get_mut("zai-test").unwrap().models.push(
            crate::config::providers::ModelEntry {
                id: "child".to_string(),
                subagent_invokable: Some(true),
                ..Default::default()
            },
        );
        cfg
    }

    #[tokio::test]
    async fn doctor_network_states_and_mutates_nothing() {
        let ok_url = one_shot_server("200 OK", r#"{"ok":true}"#).await;
        let cfg = network_cfg(ok_url);
        let before = serde_json::to_value(&cfg).unwrap();
        let (lines, failed) = provider_network_lines(&cfg, false).await;
        assert!(!failed, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("reachable · credentials verified")),
            "{lines:?}"
        );
        assert_eq!(serde_json::to_value(&cfg).unwrap(), before);

        let rejected_url = one_shot_server("401 Unauthorized", r#"{"error":"bad key"}"#).await;
        let cfg = network_cfg(rejected_url);
        let (lines, failed) = provider_network_lines(&cfg, false).await;
        assert!(failed, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("credentials REJECTED")),
            "{lines:?}"
        );
    }

    #[tokio::test]
    async fn doctor_offline_skips_network() {
        let cfg = network_cfg("http://127.0.0.1:9/v1".to_string());
        let (lines, failed) = provider_network_lines(&cfg, true).await;

        assert!(!failed);
        assert_eq!(lines, ["network checks: skipped (--offline)"]);
    }

    #[tokio::test]
    async fn doctor_unreachable_invokable_host_warns_without_failing() {
        let cfg = network_cfg_with_invokable("http://127.0.0.1:9/v1".to_string());
        let (lines, failed) = provider_network_lines(&cfg, false).await;

        assert!(!failed, "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("WARNING unreachable for subagent failover")),
            "{lines:?}"
        );
    }

    #[test]
    fn doctor_git_states() {
        let tmp = tempfile::tempdir().unwrap();
        let lines = git_lines(tmp.path());
        let rendered = lines.join("\n");

        assert!(
            rendered.contains("git: not found") || rendered.contains("git version"),
            "{rendered}"
        );
        assert!(
            rendered.contains("repo: no") || rendered.contains("repo: yes"),
            "{rendered}"
        );
    }

    #[test]
    fn doctor_exit_codes() {
        let tmp = tempfile::tempdir().unwrap();
        let snapshot = build_snapshot(base_input(tmp.path())).unwrap();
        assert!(snapshot.has_failures);

        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "local".to_string(),
            ProviderEntry {
                url: "http://127.0.0.1:11434/v1".to_string(),
                auth: Some(AuthKind::None),
                ..ProviderEntry::default()
            },
        );
        let (_lines, failed) = provider_lines(
            &cfg,
            &crate::config::extended::ExtendedConfig::default(),
            false,
        );
        assert!(!failed);
    }

    #[test]
    fn embedding_doctor_reports_resolution() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        let config_path = cockpit.join("config.json");
        std::fs::write(&config_path, r#"{"embedding_model":"openai/embed"}"#).unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "openai")
                .unwrap();
        std::fs::write(
            provider_path,
            r#"{
                "url": "https://openai.example/v1",
                "models": [
                    { "id": "embed", "embeddings": true, "embedding_dimensions": 1536 },
                    { "id": "chat" }
                ]
            }"#,
        )
        .unwrap();

        let rendered = render(&build_snapshot(base_input(tmp.path())).unwrap());

        assert!(
            rendered.contains("embedding_model: resolved openai/embed (1536 dims)"),
            "{rendered}"
        );
        assert!(
            rendered.contains("openai: 2 model(s), fetch not fetched"),
            "{rendered}"
        );
        assert!(rendered.contains("embedding-capable 1/2"), "{rendered}");
    }
}
