//! External-harness delegation tools (implementation note,
//! GOALS §6): `harness_list` and `harness_invoke`.
//!
//! These are **fixed-schema** tools (not a growing meta-tool): the set of
//! configured harnesses is fixed at session start, so per the project guidance
//! "distinct precise-schema tools where the set is fixed at start" rule we
//! ship two precise tools rather than a `(action, args)` meta-tool.
//!
//! Both are granted **only** to the primary agents `Build` and `Plan`
//! (wired in `crate::engine::builtin`); leaf subagents
//! (`explore`/`builder`/`docs`) never see them. `harness_invoke` is a
//! **leaf delegation**: the external harness runs as a leaf — it does not
//! get further cockpit delegation tools, and it doesn't break
//! leaf-termination.
//!
//! Redaction: `harness_invoke` runs the prompt through the session's
//! redaction chokepoint (`crate::harness::run`) before it reaches argv /
//! stdin / tempfile — non-bypassable (GOALS §7).

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;

use crate::config::extended::{ExtendedConfigDoc, HarnessConfig, resolve_harnesses};
use crate::engine::tool::{Tool, ToolCtx, ToolOutput, invalid_input, typed_args};
use crate::engine::validation_hint::ValidationCorrection;
use crate::harness::run::{RunContext, WritePolicy, run_harness};

// ─────────────────────────────────────────────────────────────────────
// harness_list
// ─────────────────────────────────────────────────────────────────────

/// Lists configured external harnesses, each with its models + default
/// model + PATH/auth status; supports a `refresh` probe of a harness's
/// live model list.
pub struct HarnessListTool;

#[derive(Debug, Deserialize)]
struct HarnessListArgs {
    refresh: Option<String>,
}

#[async_trait]
impl Tool for HarnessListTool {
    fn name(&self) -> &str {
        "harness_list"
    }

    fn description(&self) -> &str {
        "List configured external harnesses (e.g. `harness:codex`, `harness:claude`, `harness:opencode`) and their available models. Not a provider catalog."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "List configured external harnesses (e.g. `harness:codex`, `harness:claude`, \
             `harness:opencode`) and their available models. Not a provider catalog. Shows each \
             external harness's default model, PATH/auth status, and static or probed harness \
             models. Call this before `harness_invoke` to pick an external harness selector. \
             Pass `refresh` with `harness:<id>` to re-probe that harness's live model list; omit \
             it to read the current config."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "refresh": {
                    "type": "string",
                    "description": "External harness selector to re-probe for harness models, e.g. `harness:codex`; not a provider id"
                }
            }
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "refresh": {
                    "type": "string",
                    "description": "The external harness selector to re-probe for its live harness model list and cache the result, e.g. `harness:codex`; omit to read the current configuration. Not a provider catalog."
                }
            }
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: HarnessListArgs = typed_args(args)?;
        let cwd = ctx.cwd.clone();
        let refresh = args
            .refresh
            .as_deref()
            .map(|raw| normalize_harness_selector(raw, &cwd))
            .transpose()?;
        require_workspace_trust_for_harness_spawn()?;
        let env_overlay = ctx
            .env_overlay
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();

        if let Some(name) = refresh {
            return refresh_models(&name, &cwd, &env_overlay).await;
        }

        let harnesses = resolve_harnesses(&cwd);
        if harnesses.is_empty() {
            return Ok(ToolOutput::text(
                "No external harnesses are configured. Add one in /settings → Harnesses \
                 (verified presets: claude, codex, opencode, copilot, goose).",
            ));
        }
        // Deterministic order for a stable, cache-friendly listing.
        let mut names: Vec<&String> = harnesses.keys().collect();
        names.sort();
        let mut out = String::from("Configured external harnesses:\n");
        for name in names {
            let hc = &harnesses[name];
            let status = harness_status(name, hc, &cwd, &env_overlay).await;
            out.push_str(&format!("- {}: {status}\n", harness_selector(name)));
            if let Some(dm) = &hc.default_model {
                out.push_str(&format!("    default model: {dm}\n"));
            }
            if hc.models.is_empty() {
                out.push_str("    models: (none listed");
                if !hc.model_list_args.is_empty() {
                    out.push_str("; run harness_list with refresh to probe harness models");
                }
                out.push_str(")\n");
            } else {
                let shown: Vec<&str> = hc.models.iter().take(20).map(String::as_str).collect();
                out.push_str(&format!("    models: {}", shown.join(", ")));
                if hc.models.len() > 20 {
                    out.push_str(&format!(" … (+{} more)", hc.models.len() - 20));
                }
                out.push('\n');
            }
        }
        Ok(ToolOutput::text(out))
    }
}

/// One-line PATH/auth status for a harness, computed via the preflight
/// helper (so the listing reflects exactly what `harness_invoke` would
/// check).
async fn harness_status(
    name: &str,
    hc: &HarnessConfig,
    cwd: &std::path::Path,
    env_overlay: &std::collections::HashMap<String, String>,
) -> String {
    match crate::harness::preflight_with_env(name, hc, cwd, Some(env_overlay)).await {
        Ok(()) => "on PATH, authenticated".to_string(),
        Err(crate::harness::PreflightError::NotOnPath { .. }) => "NOT on PATH".to_string(),
        Err(crate::harness::PreflightError::NotAuthenticated { .. }) => {
            "on PATH, NOT authenticated".to_string()
        }
    }
}

/// Re-probe `name`'s live model list and cache it back into the config
/// layer that defines the harness. Falls back to the static list silently
/// when the harness can't list models.
async fn refresh_models(
    name: &str,
    cwd: &std::path::Path,
    env_overlay: &std::collections::HashMap<String, String>,
) -> Result<ToolOutput> {
    let harnesses = resolve_harnesses(cwd);
    let Some(hc) = harnesses.get(name) else {
        return Err(invalid_input(format!(
            "unknown external harness `{}`; run `harness_list` to see configured harnesses",
            harness_selector(name)
        )));
    };
    if hc.model_list_args.is_empty() {
        return Ok(ToolOutput::text(format!(
            "using external harness `{}`\n{} has no model-list command; keeping its static list ({} models).",
            harness_selector(name),
            harness_selector(name),
            hc.models.len()
        )));
    }
    match crate::harness::probe_models(hc, cwd, Some(env_overlay)).await {
        Some(models) => {
            let count = models.len();
            persist_models(name, models, cwd);
            Ok(ToolOutput::text(format!(
                "using external harness `{}`\nRefreshed harness models for `{}`: cached {count} live models into config.",
                harness_selector(name),
                harness_selector(name)
            )))
        }
        None => Ok(ToolOutput::text(format!(
            "using external harness `{}`\n{}: model-list probe returned nothing; keeping the static list ({} models).",
            harness_selector(name),
            harness_selector(name),
            hc.models.len()
        ))),
    }
}

/// Write `models` into the `models` field of `name`'s harness entry, in
/// the most-specific config layer that already defines it (else the
/// most-specific writable layer). Best-effort: a write failure is logged,
/// never surfaced as a tool error (the probe still succeeded).
fn persist_models(name: &str, models: Vec<String>, cwd: &std::path::Path) {
    use crate::config::dirs::discover_config_dirs;
    let dirs = discover_config_dirs(cwd);
    // Prefer the most-specific layer (last in walk order) that defines the
    // harness; else the most-specific layer overall.
    let mut target: Option<std::path::PathBuf> = None;
    let mut defining: Option<std::path::PathBuf> = None;
    for dir in &dirs {
        let path = dir.path.join(crate::config::dirs::CONFIG_FILE);
        target = Some(path.clone());
        if let Ok(doc) = ExtendedConfigDoc::load(&path)
            && doc.config().harnesses.contains_key(name)
        {
            defining = Some(path);
        }
    }
    let Some(path) = defining.or(target) else {
        tracing::debug!(harness = %name, "no config layer to persist refreshed models");
        return;
    };
    let Ok(mut doc) = ExtendedConfigDoc::load(&path) else {
        return;
    };
    let mut cfg = doc.config();
    match cfg.harnesses.get_mut(name) {
        Some(entry) => entry.models = models,
        None => {
            // The harness is only defined in a lower layer; materialize an
            // override entry here carrying just the refreshed models is not
            // enough (it'd miss `command`). Instead, write the full merged
            // entry so the cached layer is self-contained.
            let merged = resolve_harnesses(cwd);
            if let Some(mut full) = merged.get(name).cloned() {
                full.models = models;
                cfg.harnesses.insert(name.to_string(), full);
            }
        }
    }
    if let Err(e) = doc.write(&cfg) {
        tracing::debug!(harness = %name, error = %e, "persisting refreshed models failed");
    }
}

// ─────────────────────────────────────────────────────────────────────
// harness_invoke
// ─────────────────────────────────────────────────────────────────────

/// Runs a configured external harness non-interactively on a prompt and
/// returns its structured result (a leaf delegation).
pub struct HarnessInvokeTool;

#[derive(Debug, Deserialize)]
struct HarnessInvokeArgs {
    harness: String,
    model: Option<String>,
    prompt: String,
    write: Option<String>,
}

#[async_trait]
impl Tool for HarnessInvokeTool {
    fn name(&self) -> &str {
        "harness_invoke"
    }

    fn description(&self) -> &str {
        "Run a configured external harness selector on a prompt; use `task` for Cockpit subagent delegation."
    }

    fn defensive_description(&self) -> Option<String> {
        Some(
            "Delegate a self-contained unit of work to an external harness selector such as \
             `harness:claude`, `harness:codex`, or `harness:opencode`. Use `task` instead for \
             Cockpit subagent delegation. Pass `harness` (one listed by `harness_list`), an \
             optional harness `model` (defaults to the harness's default), and a complete \
             standalone `prompt` — the external harness sees only this prompt, not your \
             conversation. It runs as a leaf and blocks until it finishes or times out. In Build \
             mode the harness writes to the project directly; in Plan mode it runs isolated and \
             returns a diff (override with `write`)."
                .to_string(),
        )
    }

    fn parameters(&self) -> Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "harness": { "type": "string", "description": "External harness selector, e.g. `harness:codex`; not a provider id" },
                "model":   { "type": "string", "description": "External harness model override" },
                "prompt":  { "type": "string", "description": "Self-contained task brief" },
                "write":   { "type": "string", "description": "Write-policy override", "enum": ["direct", "isolated"] }
            },
            "required": ["harness", "prompt"]
        })
    }

    fn defensive_parameters(&self) -> Option<Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "harness": { "type": "string", "description": "The external harness selector to run, as shown by `harness_list` (for example `harness:codex`). Do not pass provider ids here" },
                "model":   { "type": "string", "description": "Optional external harness model to run; omit to use the harness's configured default model" },
                "prompt":  { "type": "string", "description": "A complete, standalone task brief for the external harness: the goal, constraints, exact files in scope, and what \"done\" looks like. The harness cannot see this conversation, so include everything it needs" },
                "write":   { "type": "string", "description": "Optional override of the write policy: `direct` lets the harness write to the project directory, `isolated` runs it in a throwaway worktree and returns a diff without applying it. Omit to use the default for the active mode (Build → direct, Plan → isolated)", "enum": ["direct", "isolated"] }
            },
            "required": ["harness", "prompt"]
        }))
    }

    async fn call(&self, args: Value, ctx: &ToolCtx) -> Result<ToolOutput> {
        let args: HarnessInvokeArgs = typed_args(args)?;
        let harness_name = normalize_harness_selector(&args.harness, &ctx.cwd)?;
        if args.prompt.trim().is_empty() {
            return Err(invalid_input("`prompt` is required (the task brief)"));
        }
        let prompt = args.prompt;
        let explicit_model = args
            .model
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        let write_override = match args.write.as_deref() {
            Some(raw) => {
                let policy = WritePolicy::parse_override(raw).ok_or_else(|| {
                    invalid_input("`write` must be either `direct` or `isolated`")
                })?;
                if policy == WritePolicy::Direct
                    && !WritePolicy::direct_allowed_for_agent(&ctx.agent_id)
                {
                    return Err(invalid_input(format!(
                        "`{}` cannot invoke harnesses with `write=\"direct\"`; switch to Build \
                         or omit `write` to use isolated mode",
                        ctx.agent_id
                    )));
                }
                Some(policy)
            }
            None => None,
        };

        let cwd = ctx.cwd.clone();
        require_workspace_trust_for_harness_spawn()?;
        let env_overlay = ctx
            .env_overlay
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let harnesses = resolve_harnesses(&cwd);
        let Some(hc) = harnesses.get(&harness_name) else {
            let mut names: Vec<&String> = harnesses.keys().collect();
            names.sort();
            let list = if names.is_empty() {
                "(none configured — add one in /settings → Harnesses)".to_string()
            } else {
                names
                    .iter()
                    .map(|s| format!("`{}`", harness_selector(s)))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            return Err(invalid_input(format!(
                "unknown external harness `{}`. Configured: {list}",
                harness_selector(&harness_name)
            )));
        };

        // Model precedence: explicit override → harness default_model →
        // none (the harness picks). Validate an explicit model against the
        // known list when one is configured (lenient: a non-empty static
        // list that doesn't contain the model is a hard error so the model
        // can correct; an empty/un-probed list lets anything through).
        let model = explicit_model.clone().or_else(|| hc.default_model.clone());
        if let Some(m) = &explicit_model
            && !hc.models.is_empty()
            && !hc.models.iter().any(|known| known == m)
        {
            if let Some(provider_id) = provider_ref_in_harness_model(m, &cwd) {
                let correction = ValidationCorrection::harness_model_is_provider_ref(
                    m,
                    &harness_name,
                    &provider_id,
                );
                return Err(invalid_input(correction.model_message()));
            }
            return Err(invalid_input(format!(
                "model `{m}` is not in `{}`'s configured harness models; run `harness_list` \
                 (with refresh) to see valid harness models, or omit `model` to use the default",
                harness_selector(&harness_name)
            )));
        }

        // Write policy: the active primary's default, overridable per call.
        // The invoke tool is granted only to Build/Plan, so `ctx.agent_id`
        // is the active primary.
        let policy = write_override.unwrap_or_else(|| WritePolicy::for_primary(&ctx.agent_id));

        // Load the utility-model ref + providers for over-cap summarization
        // (reusing the auto_title-style path).
        let (extended, providers) = crate::auto_title::load_configs_for(&cwd);

        let result = run_harness(RunContext {
            harness_name: &harness_name,
            cfg: hc,
            prompt: &prompt,
            model: model.as_deref(),
            cwd: &cwd,
            agent_id: &ctx.agent_id,
            policy,
            redact: ctx.redact.clone(),
            trusted_only: ctx.session.trusted_only_flag(),
            utility_model: extended.utility_model.as_deref(),
            providers: &providers,
            env_overlay: Some(&env_overlay),
        })
        .await;

        match result {
            Ok(run) => {
                let text = format!(
                    "using external harness `{}`\n\n{}",
                    harness_selector(&harness_name),
                    run.render(&harness_name)
                );
                // A non-zero / timed-out harness is an *execution* failure
                // (environmental), surfaced as the tool's text with the
                // status line — not an InvalidToolInput. We return Ok so the
                // model sees the full diagnostic output and can react.
                Ok(ToolOutput::text(text))
            }
            // Preflight / spawn / worktree failures: actionable errors. These
            // are environmental, not bad input, so they bubble as a normal
            // (execution) error string the dispatcher surfaces.
            Err(msg) => Err(anyhow::anyhow!(msg)),
        }
    }
}

fn harness_selector(id: &str) -> String {
    format!("harness:{id}")
}

fn provider_selector(id: &str) -> String {
    format!("provider:{id}")
}

fn provider_id_error(provider_id: &str) -> anyhow::Error {
    invalid_input(format!(
        "`{provider_id}` is a provider id (`{}`), not an external harness; for provider catalogs use `cockpit fetch-models {provider_id}`",
        provider_selector(provider_id)
    ))
}

fn normalize_harness_selector(raw: &str, cwd: &std::path::Path) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(invalid_input("external harness selector is required"));
    }

    let providers = crate::config::providers::ConfigDoc::load_effective(cwd);
    if let Some(provider_id) = trimmed.strip_prefix("provider:") {
        let provider_id = provider_id.trim();
        if providers.providers.contains_key(provider_id) {
            return Err(provider_id_error(provider_id));
        }
        return Err(invalid_input(format!(
            "`{}` is a provider selector, not an external harness selector; use `harness:<id>` for external harnesses",
            provider_selector(provider_id)
        )));
    }

    let harness_id = trimmed
        .strip_prefix("harness:")
        .map(str::trim)
        .unwrap_or(trimmed);
    if harness_id.is_empty() {
        return Err(invalid_input("external harness selector is required"));
    }
    if providers.providers.contains_key(harness_id) {
        return Err(provider_id_error(harness_id));
    }
    Ok(harness_id.to_string())
}

fn provider_ref_in_harness_model(model: &str, cwd: &std::path::Path) -> Option<String> {
    let providers = crate::config::providers::ConfigDoc::load_effective(cwd);
    if providers.providers.contains_key(model) {
        return Some(model.to_string());
    }
    let (provider_id, _) = model.split_once(':')?;
    providers
        .providers
        .contains_key(provider_id)
        .then(|| provider_id.to_string())
}

fn require_workspace_trust_for_harness_spawn() -> Result<()> {
    if crate::config::trust::runtime_policy().is_some() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "harness spawn blocked: workspace trust policy is not resolved for this session"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn with_trusted_workspace<T>(
        cwd: &std::path::Path,
        f: impl std::future::Future<Output = T>,
    ) -> T {
        let policy = crate::config::trust::WorkspaceTrustPolicy {
            root: crate::config::trust::resolve_trust_root(cwd).unwrap(),
            mode: crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        };
        crate::config::trust::scope_workspace_trust_policy(policy, f).await
    }

    #[test]
    fn invoke_schema_is_fixed_and_requires_harness_and_prompt() {
        let tool = HarnessInvokeTool;
        for schema in [tool.parameters(), tool.defensive_parameters().unwrap()] {
            let props = schema["properties"].as_object().unwrap();
            for key in ["harness", "model", "prompt", "write"] {
                assert!(props.contains_key(key), "missing `{key}` in {schema}");
            }
            let required: Vec<&str> = schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .collect();
            assert_eq!(required, vec!["harness", "prompt"]);
            // `write` is a constrained enum in both modes.
            let write_enum = schema["properties"]["write"]["enum"].as_array().unwrap();
            assert_eq!(write_enum.len(), 2);
        }
    }

    #[tokio::test]
    async fn plan_direct_write_override_is_rejected_before_invoke() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.agent_id = "Plan".to_string();
        let err = HarnessInvokeTool
            .call(
                serde_json::json!({
                    "harness": "missing",
                    "prompt": "do work",
                    "write": "direct",
                }),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cannot invoke harnesses"), "{err}");
    }

    #[tokio::test]
    async fn build_direct_write_override_reaches_harness_lookup() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.agent_id = "Build".to_string();
        let err = with_trusted_workspace(tmp.path(), async {
            HarnessInvokeTool
                .call(
                    serde_json::json!({
                        "harness": "missing",
                        "prompt": "do work",
                        "write": "direct",
                    }),
                    &ctx,
                )
                .await
                .unwrap_err()
        })
        .await;
        assert!(
            err.to_string().contains("unknown external harness"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn provider_model_override_points_to_provider_fetch_path() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        std::fs::write(
            cockpit.join("config.json"),
            r#"{"harnesses":{"claude":{"command":"claude","models":["sonnet"]}}}"#,
        )
        .unwrap();
        std::fs::write(
            cockpit.join("providers/openai.json"),
            r#"{"url":"https://api.openai.example/v1"}"#,
        )
        .unwrap();
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.agent_id = "Build".to_string();

        let err = with_trusted_workspace(tmp.path(), async {
            HarnessInvokeTool
                .call(
                    serde_json::json!({
                        "harness": "claude",
                        "model": "openai:gpt-4o",
                        "prompt": "do work",
                    }),
                    &ctx,
                )
                .await
                .unwrap_err()
        })
        .await;

        let msg = err.to_string();
        assert!(msg.contains("provider `openai`"), "{msg}");
        assert!(msg.contains("harness_invoke expects"), "{msg}");
        assert!(msg.contains("cockpit fetch-models openai"), "{msg}");
    }

    #[tokio::test]
    async fn list_refresh_provider_id_is_rejected_before_workspace_trust() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        std::fs::write(
            cockpit.join("providers/codex-oauth.json"),
            r#"{"url":"https://chatgpt.com/backend-api/codex"}"#,
        )
        .unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());

        let err = HarnessListTool
            .call(serde_json::json!({ "refresh": "codex-oauth" }), &ctx)
            .await
            .unwrap_err();

        assert_eq!(
            err.to_string(),
            "`codex-oauth` is a provider id (`provider:codex-oauth`), not an external harness; for provider catalogs use `cockpit fetch-models codex-oauth`"
        );
    }

    #[tokio::test]
    async fn invoke_provider_id_is_rejected_before_workspace_trust() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        std::fs::create_dir_all(cockpit.join("providers")).unwrap();
        std::fs::write(
            cockpit.join("providers/codex-oauth.json"),
            r#"{"url":"https://chatgpt.com/backend-api/codex"}"#,
        )
        .unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());

        let err = HarnessInvokeTool
            .call(
                serde_json::json!({
                    "harness": "provider:codex-oauth",
                    "prompt": "do work"
                }),
                &ctx,
            )
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains(
                "`codex-oauth` is a provider id (`provider:codex-oauth`), not an external harness"
            ),
            "{err}"
        );
        assert!(!err.to_string().contains("workspace trust"), "{err}");
    }

    #[tokio::test]
    async fn list_renders_namespaced_harness_selectors() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".cockpit")).unwrap();
        std::fs::write(
            tmp.path().join(".cockpit/config.json"),
            r#"{"harnesses":{"codex":{"command":"true"}}}"#,
        )
        .unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());

        let out = with_trusted_workspace(tmp.path(), async {
            HarnessListTool
                .call(serde_json::json!({}), &ctx)
                .await
                .unwrap()
                .content
        })
        .await;

        assert!(out.contains("harness:codex"), "{out}");
    }

    #[tokio::test]
    async fn invalid_write_override_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let ctx = crate::tools::common::test_ctx(tmp.path());
        let err = HarnessInvokeTool
            .call(
                serde_json::json!({
                    "harness": "missing",
                    "prompt": "do work",
                    "write": "unsafe",
                }),
                &ctx,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("must be either"), "{err}");
    }

    #[tokio::test]
    async fn invoke_without_workspace_trust_is_blocked_before_lookup() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = crate::tools::common::test_ctx(tmp.path());
        ctx.agent_id = "Build".to_string();
        let err = HarnessInvokeTool
            .call(
                serde_json::json!({
                    "harness": "missing",
                    "prompt": "do work",
                }),
                &ctx,
            )
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("workspace trust policy is not resolved"),
            "{msg}"
        );
        assert!(!msg.contains("unknown harness"), "{msg}");
    }

    #[test]
    fn list_schema_has_optional_refresh() {
        let tool = HarnessListTool;
        for schema in [tool.parameters(), tool.defensive_parameters().unwrap()] {
            assert!(schema["properties"]["refresh"].is_object());
            // No required fields — refresh is optional.
            assert!(schema.get("required").is_none());
        }
    }

    #[test]
    fn list_description_disambiguates_external_harnesses_from_providers() {
        let tool = HarnessListTool;
        let description = tool.description();

        assert!(description.contains("external"), "{description}");
        assert!(description.contains("provider"), "{description}");
        assert!(description.contains("harness:codex"), "{description}");
    }

    #[test]
    fn invoke_description_points_subagent_delegation_to_task() {
        let tool = HarnessInvokeTool;

        assert!(
            tool.description().contains("`task`"),
            "{}",
            tool.description()
        );
        assert!(
            tool.defensive_description()
                .unwrap()
                .contains("Use `task` instead for Cockpit subagent delegation")
        );
    }

    #[test]
    fn tool_names_are_stable() {
        assert_eq!(HarnessListTool.name(), "harness_list");
        assert_eq!(HarnessInvokeTool.name(), "harness_invoke");
    }
}
