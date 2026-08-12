//! `cockpit fetch-models` — refresh every configured provider's model
//! catalog by hitting its OpenAI-compatible `/models` endpoint.
//!
//! Drift policy: if the upstream listing omits a model the user already
//! has configured, the command prompts with three options and a
//! "don't ask again" toggle. The non-interactive `--on-unlisted` flag
//! bypasses the prompt (CI use). The chosen default is persisted as
//! `on_unlisted_models_fetch` under `config.json` so future runs skip
//! the prompt.

use std::collections::BTreeSet;
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::cli::FetchModelsArgs;
use crate::config::dirs::most_specific_config_write_target;
use crate::config::providers::{
    ConfigDoc, ModelMergePolicy, OnUnlistedModelsFetch, ProviderEntry, ProviderModelCatalog,
    ProviderModelFetchDisplayState, ProvidersConfig, merge_fetched_models_with_policy,
    provider_model_fetch_display_state, redact_model_fetch_reason,
};
use crate::providers::models_fetch::{self, FetchOutcome, persist_provider};
use crate::providers::{ProviderTemplate, template_by_id};

/// Exact CLI line when a selected provider's effective template has no
/// published `/models` endpoint (no HTTP, no config write).
pub(crate) fn models_endpoint_unsupported_message(
    provider_id: &str,
    template: &ProviderTemplate,
) -> String {
    format!(
        "Provider `{provider_id}` ({}) has no published /models endpoint. Configure models with `cockpit provider add {}` or `/setup model`.",
        template.display, template.id
    )
}

/// Preflight: if the entry's effective template refuses `/models`, return
/// that template so the caller can skip request resolution entirely.
pub(crate) fn template_without_models_endpoint(
    provider_id: &str,
    entry: &ProviderEntry,
) -> Option<&'static ProviderTemplate> {
    let template_id = entry.effective_template(provider_id)?;
    let template = template_by_id(template_id)?;
    if template.supports_models_endpoint {
        None
    } else {
        Some(template)
    }
}

pub async fn run(args: FetchModelsArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("getting cwd")?;
    let mut cfg = crate::secret_ref::load_effective(&cwd);
    let provider_filter = match (args.provider_arg.as_ref(), args.provider.as_ref()) {
        (Some(_), Some(_)) => {
            anyhow::bail!("pass provider id once, either positionally or with --provider")
        }
        (Some(p), None) | (None, Some(p)) => Some(p),
        (None, None) => None,
    };

    if args.deep {
        return run_deepfetch(
            &cwd,
            &mut cfg,
            provider_filter.cloned(),
            args.model,
            args.yes,
        )
        .await;
    }

    let policy_override = match args.on_unlisted.as_deref() {
        Some("keep") => Some(OnUnlistedModelsFetch::Keep),
        Some("remove") => Some(OnUnlistedModelsFetch::Remove),
        Some("ask") => Some(OnUnlistedModelsFetch::Ask),
        Some(other) => anyhow::bail!("--on-unlisted must be keep|remove|ask, got `{other}`"),
        None => None,
    };

    let targets: Vec<String> = if let Some(p) = provider_filter {
        if !cfg.providers.contains_key(p) {
            anyhow::bail!("no provider with id `{p}` in effective config");
        }
        vec![p.clone()]
    } else {
        cfg.providers.keys().cloned().collect()
    };

    if targets.is_empty() {
        println!("no providers configured");
        return Ok(());
    }

    let mut summaries: Vec<(String, Result<FetchOutcome, anyhow::Error>)> = Vec::new();
    for id in &targets {
        let entry = cfg.providers.get(id).expect("filtered above").clone();
        println!("→ {id} ({})", entry.url);

        // Preflight by effective template before any request resolution so
        // providers without a published /models endpoint (e.g. Nous Research)
        // never hit the network or mutate config.
        if let Some(template) = template_without_models_endpoint(id, &entry) {
            println!("{}", models_endpoint_unsupported_message(id, template));
            continue;
        }

        let resolved = match models_fetch::resolve_provider_request_async(id, &entry).await {
            Ok(r) => r,
            Err(e) => {
                println!("  ⚠ skipped: {e}");
                summaries.push((id.clone(), Err(e)));
                continue;
            }
        };

        let outcome =
            models_fetch::fetch_models_for_provider(id, &entry, &resolved, Duration::from_secs(15))
                .await;

        print_fetch_outcome(&outcome, args.allow_fallback);
        summaries.push((id.clone(), outcome));
    }

    let mut fallback_uses = BTreeSet::new();
    let mut fallback_keeps = BTreeSet::new();
    if !args.allow_fallback {
        resolve_interactive_fallbacks(
            &mut summaries,
            &mut cfg,
            &mut fallback_uses,
            &mut fallback_keeps,
        )
        .await?;
    }

    // Detect drift (config models not in remote) before mutating cfg.
    let drift: Vec<(String, Vec<String>)> = summaries
        .iter()
        .filter_map(|(id, outcome)| {
            let remote = match outcome {
                Ok(FetchOutcome::Models { models, .. }) => models,
                Ok(FetchOutcome::FallbackAvailable { models, .. })
                    if args.allow_fallback || fallback_uses.contains(id) =>
                {
                    models
                }
                _ => return None,
            };
            let entry = cfg.providers.get(id)?;
            let missing: Vec<String> = entry
                .models
                .iter()
                .filter(|m| !m.manual)
                .filter(|m| !remote.iter().any(|r| r.id == m.id))
                .map(|m| m.id.clone())
                .collect();
            if missing.is_empty() {
                None
            } else {
                Some((id.clone(), missing))
            }
        })
        .collect();

    let stored_policy_before = cfg.on_unlisted_models_fetch;
    let decision = pick_policy(&mut cfg, policy_override, &drift)?;
    if cfg.on_unlisted_models_fetch != stored_policy_before {
        persist_unlisted_policy(&cwd, cfg.on_unlisted_models_fetch)?;
    }

    // Apply decisions.
    let mut failures: Vec<(String, String)> = Vec::new();
    for (id, outcome) in summaries {
        match outcome {
            Ok(FetchOutcome::Models { models, catalog }) => {
                let entry = cfg.providers.get_mut(&id).expect("populated");
                apply_models(&id, entry, models, catalog, None, decision);
                persist_provider(&cwd, &id, entry.clone())?;
            }
            Ok(FetchOutcome::FallbackAvailable {
                models,
                catalog,
                reason,
            }) if args.allow_fallback || fallback_uses.contains(&id) => {
                let entry = cfg.providers.get_mut(&id).expect("populated");
                apply_models(&id, entry, models, catalog, Some(reason), decision);
                persist_provider(&cwd, &id, entry.clone())?;
            }
            Ok(FetchOutcome::FallbackAvailable { reason, .. }) => {
                let reason = redact_model_fetch_reason(reason);
                let entry = cfg.providers.get_mut(&id).expect("populated");
                entry.mark_model_fetch_failed_kept_existing(reason.clone());
                persist_provider(&cwd, &id, entry.clone())?;
                if !fallback_keeps.contains(&id) {
                    failures.push((id, reason));
                }
            }
            Ok(FetchOutcome::Unsupported) => {
                let entry = cfg.providers.get_mut(&id).expect("populated");
                entry.mark_model_fetch_unsupported();
                persist_provider(&cwd, &id, entry.clone())?;
            }
            Err(error) => {
                let reason = error.to_string();
                if let Some(entry) = cfg.providers.get_mut(&id) {
                    entry.mark_model_fetch_failed_kept_existing(reason.clone());
                    persist_provider(&cwd, &id, entry.clone())?;
                }
                failures.push((id, reason));
            }
        }
    }

    println!();
    print!("{}", fetch_status_summary(&cfg, &targets));

    if !failures.is_empty() {
        anyhow::bail!(
            "fetch-models failed for {} provider(s); existing catalogs kept",
            failures.len()
        );
    }

    println!("config.json updated.");
    Ok(())
}

async fn run_deepfetch(
    cwd: &Path,
    cfg: &mut ProvidersConfig,
    provider_filter: Option<String>,
    model_filter: Option<String>,
    assume_yes: bool,
) -> Result<()> {
    use crate::providers::deepfetch::{
        DeepfetchMode, DeepfetchScope, HttpDeepfetchProbeClient, collect_deepfetch_targets,
        deepfetch_confirmation_message, format_deepfetch_report, plan_deepfetch, probe_target,
        should_run_deepfetch,
    };

    let scope = DeepfetchScope {
        provider: provider_filter,
        model: model_filter,
    };
    let targets = collect_deepfetch_targets(cfg, &scope)?;
    if targets.is_empty() {
        println!("deep fetch: no eligible OpenAI-compatible non-embedding models");
        return Ok(());
    }
    let plan = plan_deepfetch(&targets);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mode = if assume_yes {
        DeepfetchMode::AssumeYes
    } else if stdin.is_terminal() && stdout.is_terminal() {
        DeepfetchMode::Interactive
    } else {
        DeepfetchMode::NonInteractive
    };
    let confirmed = if matches!(mode, DeepfetchMode::Interactive) {
        let mut input = stdin.lock();
        let mut output = stdout.lock();
        write!(output, "{}", deepfetch_confirmation_message(&plan)).ok();
        output.flush().ok();
        let mut line = String::new();
        input.read_line(&mut line).ok();
        matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    } else {
        false
    };
    if !should_run_deepfetch(mode, confirmed, stdin.is_terminal() && stdout.is_terminal())? {
        println!("deep fetch cancelled before sending any probe requests");
        return Ok(());
    }
    if assume_yes {
        println!("{}", deepfetch_confirmation_message(&plan));
    }

    let mut resolved = std::collections::BTreeMap::new();
    for target in &targets {
        if resolved.contains_key(&target.provider_id) {
            continue;
        }
        let entry = cfg
            .providers
            .get(&target.provider_id)
            .expect("target came from config")
            .clone();
        let request = models_fetch::resolve_provider_request_async(&target.provider_id, &entry)
            .await
            .with_context(|| format!("resolving provider `{}`", target.provider_id))?;
        resolved.insert(target.provider_id.clone(), request);
    }

    let mut client = HttpDeepfetchProbeClient::new(resolved, Duration::from_secs(20));
    let cancel = tokio::signal::ctrl_c();
    tokio::pin!(cancel);
    let mut cancelled = false;
    for target in &targets {
        println!("→ deep fetch {}:{}", target.provider_id, target.model_id);
        let report = tokio::select! {
            result = probe_target(&mut client, cfg, target) => result?,
            _ = &mut cancel => {
                cancelled = true;
                println!("deep fetch cancelled; completed model results have already been saved");
                break;
            }
        };
        println!("  {}", format_deepfetch_report(&report));
        let entry = cfg
            .providers
            .get(&target.provider_id)
            .expect("target came from config")
            .clone();
        persist_provider(cwd, &target.provider_id, entry)?;
    }
    if cancelled {
        return Ok(());
    }
    println!(
        "deep fetch complete: {} model(s), up to {} request(s)",
        plan.models,
        plan.total_requests()
    );
    Ok(())
}

fn fetch_status_summary(cfg: &ProvidersConfig, targets: &[String]) -> String {
    let mut by_state: Vec<(ProviderModelFetchDisplayState, Vec<String>)> =
        ProviderModelFetchDisplayState::ALL
            .into_iter()
            .map(|state| (state, Vec::new()))
            .collect();

    for id in targets {
        let Some(entry) = cfg.providers.get(id) else {
            continue;
        };
        let state = provider_model_fetch_display_state(entry);
        let (_, ids) = by_state
            .iter_mut()
            .find(|(candidate, _)| *candidate == state)
            .expect("all display states covered");
        ids.push(id.clone());
    }

    let mut out = format!("total providers: {}\n", targets.len());
    for (state, ids) in by_state {
        let label = format!("{}:", state.label());
        out.push_str(&format!("{label:<12}{:>3}", ids.len()));
        if state != ProviderModelFetchDisplayState::Live && !ids.is_empty() {
            out.push_str(" (");
            out.push_str(&ids.join(", "));
            out.push(')');
        }
        out.push('\n');
    }
    out
}

fn print_fetch_outcome(outcome: &Result<FetchOutcome, anyhow::Error>, allow_fallback: bool) {
    let line = fetch_outcome_line(outcome, allow_fallback);
    println!("  {line}");
}

fn fetch_outcome_line(
    outcome: &Result<FetchOutcome, anyhow::Error>,
    allow_fallback: bool,
) -> String {
    match outcome {
        Ok(FetchOutcome::Models { models, catalog }) => {
            let suffix = if matches!(catalog, ProviderModelCatalog::CodexFallback) {
                " (fallback catalog)"
            } else {
                ""
            };
            format!("✓ {} provider model(s) fetched{suffix}", models.len())
        }
        Ok(FetchOutcome::FallbackAvailable { models, reason, .. }) => {
            let reason = redact_model_fetch_reason(reason.as_str());
            if allow_fallback {
                let prefix = if reason.contains("empty model list") {
                    "⚠ live fetch returned an empty model list"
                } else {
                    "⚠ live fetch failed"
                };
                format!(
                    "{prefix}; activating fallback catalog with {} model(s): {reason}",
                    models.len()
                )
            } else {
                format!(
                    "✗ live fetch failed; kept existing catalog. Fallback available with --allow-fallback: {reason}"
                )
            }
        }
        Ok(FetchOutcome::Unsupported) => "· no /models endpoint (404) — skipped".to_string(),
        Err(e) => {
            format!("✗ {}", redact_model_fetch_reason(e.to_string()))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FallbackDecision {
    Retry,
    Keep,
    UseFallback,
    Cancel,
}

async fn resolve_interactive_fallbacks(
    summaries: &mut [(String, Result<FetchOutcome, anyhow::Error>)],
    cfg: &mut ProvidersConfig,
    fallback_uses: &mut BTreeSet<String>,
    fallback_keeps: &mut BTreeSet<String>,
) -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if !stdin.is_terminal() || !stdout.is_terminal() {
        return Ok(());
    }

    for (provider_id, outcome_slot) in summaries.iter_mut() {
        while let Ok(FetchOutcome::FallbackAvailable { reason, .. }) = outcome_slot {
            let provider_id = provider_id.clone();
            let redacted_reason = redact_model_fetch_reason(reason.as_str());
            let decision = {
                let mut input = stdin.lock();
                let mut output = stdout.lock();
                pick_fallback_decision_with_io(
                    &provider_id,
                    &redacted_reason,
                    &mut input,
                    &mut output,
                )?
            };

            match decision {
                FallbackDecision::Retry => {
                    let entry = cfg
                        .providers
                        .get(&provider_id)
                        .expect("filtered above")
                        .clone();
                    println!("→ {provider_id} ({})", entry.url);
                    println!("  retrying live /models...");
                    let outcome =
                        match models_fetch::resolve_provider_request_async(&provider_id, &entry)
                            .await
                        {
                            Ok(resolved) => {
                                models_fetch::fetch_models_for_provider(
                                    &provider_id,
                                    &entry,
                                    &resolved,
                                    Duration::from_secs(15),
                                )
                                .await
                            }
                            Err(error) => Err(error),
                        };
                    print_fetch_outcome(&outcome, false);
                    *outcome_slot = outcome;
                }
                FallbackDecision::Keep => {
                    fallback_keeps.insert(provider_id);
                    break;
                }
                FallbackDecision::UseFallback => {
                    fallback_uses.insert(provider_id);
                    break;
                }
                FallbackDecision::Cancel => {
                    anyhow::bail!("fetch-models cancelled");
                }
            }
        }
    }

    Ok(())
}

fn pick_fallback_decision_with_io(
    provider_id: &str,
    reason: &str,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
) -> Result<FallbackDecision> {
    writeln!(output).ok();
    writeln!(output, "`{provider_id}` live /models fetch failed:").ok();
    writeln!(output, "  {reason}").ok();
    writeln!(output).ok();
    writeln!(output, "  [1] Retry live fetch").ok();
    writeln!(output, "  [2] Keep existing catalog (default)").ok();
    writeln!(output, "  [3] Use fallback catalog").ok();
    writeln!(output, "  [4] Cancel").ok();
    write!(output, "Choose 1/2/3/4: ").ok();
    output.flush().ok();

    let mut buf = String::new();
    input.read_line(&mut buf).ok();
    let decision = match buf.trim().to_ascii_lowercase().as_str() {
        "1" | "r" | "retry" => FallbackDecision::Retry,
        "3" | "f" | "fallback" | "use" => FallbackDecision::UseFallback,
        "4" | "c" | "cancel" | "q" | "quit" => FallbackDecision::Cancel,
        _ => FallbackDecision::Keep,
    };
    Ok(decision)
}

pub(crate) fn persist_unlisted_policy(
    cwd: &Path,
    on_unlisted_models_fetch: Option<OnUnlistedModelsFetch>,
) -> Result<()> {
    let path = most_specific_config_write_target(cwd).ok_or_else(|| {
        anyhow::anyhow!("no cockpit config found — run `/settings` inside the TUI to create one")
    })?;
    let mut doc = ConfigDoc::load(&path)?;
    doc.write_unlisted_models_policy(on_unlisted_models_fetch)
        .context("writing config.json")
}

fn apply_models(
    provider_id: &str,
    entry: &mut ProviderEntry,
    remote: Vec<crate::config::providers::ModelEntry>,
    catalog: ProviderModelCatalog,
    fallback_reason: Option<String>,
    decision: OnUnlistedModelsFetch,
) {
    let policy = match decision {
        OnUnlistedModelsFetch::Keep => ModelMergePolicy::KeepUnlisted,
        // Ask reaches this point only after interactive prompting, except for
        // an explicit `--on-unlisted ask`; preserve the historical concrete
        // behavior for that non-interactive path by removing unlisted models.
        OnUnlistedModelsFetch::Remove | OnUnlistedModelsFetch::Ask => {
            ModelMergePolicy::RemoveUnlisted
        }
    };
    entry.models = merge_fetched_models_with_policy(
        entry.effective_template(provider_id),
        &entry.models,
        remote,
        policy,
    );
    entry.models_fetched_at = Some(chrono::Utc::now());
    entry.model_catalog = catalog;
    if let Some(reason) = fallback_reason {
        entry.mark_model_fetch_fallback(reason);
    } else {
        entry.mark_model_fetch_success(catalog);
    }
}

fn pick_policy(
    cfg: &mut ProvidersConfig,
    explicit: Option<OnUnlistedModelsFetch>,
    drift: &[(String, Vec<String>)],
) -> Result<OnUnlistedModelsFetch> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let is_interactive = stdin.is_terminal() && stdout.is_terminal();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();
    let mut stderr = std::io::stderr().lock();
    pick_policy_with_io(
        cfg,
        explicit,
        drift,
        is_interactive,
        &mut stdin,
        &mut stdout,
        &mut stderr,
    )
}

fn pick_policy_with_io(
    cfg: &mut ProvidersConfig,
    explicit: Option<OnUnlistedModelsFetch>,
    drift: &[(String, Vec<String>)],
    is_interactive: bool,
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    notice: &mut dyn Write,
) -> Result<OnUnlistedModelsFetch> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if drift.is_empty() {
        return Ok(cfg
            .on_unlisted_models_fetch
            .unwrap_or(OnUnlistedModelsFetch::Keep));
    }
    let stored = cfg.on_unlisted_models_fetch;
    if matches!(stored, Some(OnUnlistedModelsFetch::Keep))
        || matches!(stored, Some(OnUnlistedModelsFetch::Remove))
    {
        return Ok(stored.unwrap());
    }
    if !is_interactive {
        writeln!(
            notice,
            "Noninteractive fetch-models run kept unlisted configured models. Use --on-unlisted keep or --on-unlisted remove to choose explicitly."
        )
        .ok();
        return Ok(OnUnlistedModelsFetch::Keep);
    }

    // Interactive prompt.
    writeln!(output).ok();
    writeln!(
        output,
        "Some configured models are not in the upstream /models list:"
    )
    .ok();
    for (pid, mids) in drift {
        for mid in mids {
            writeln!(output, "  {pid} › {mid}").ok();
        }
    }
    writeln!(output).ok();
    writeln!(output, "  [1] Don't remove unlisted models (default)").ok();
    writeln!(output, "  [2] Remove unlisted models").ok();
    writeln!(output, "  [3] Don't ask again (apply default, persist)").ok();
    write!(output, "Choose 1/2/3: ").ok();
    output.flush().ok();

    let mut buf = String::new();
    input.read_line(&mut buf).ok();
    let pick = match buf.trim() {
        "2" => OnUnlistedModelsFetch::Remove,
        "3" => {
            cfg.on_unlisted_models_fetch = Some(OnUnlistedModelsFetch::Keep);
            OnUnlistedModelsFetch::Keep
        }
        _ => OnUnlistedModelsFetch::Keep,
    };
    Ok(pick)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn untrusted_project_providers_are_not_loaded() {
        let tmp = tempfile::tempdir().unwrap();
        let _env = crate::test_env::lock();
        crate::config::trust::clear_runtime_policy_for_tests();
        let cockpit = tmp.path().join(".cockpit/providers");
        std::fs::create_dir_all(&cockpit).unwrap();
        std::fs::write(
            cockpit.join("attacker.json"),
            r#"{ "url": "https://attacker.example/v1" }"#,
        )
        .unwrap();
        let root = crate::config::trust::resolve_trust_root(tmp.path()).unwrap();
        crate::config::trust::set_runtime_policy(
            root,
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        );

        let cfg = crate::secret_ref::load_effective(tmp.path());
        assert!(!cfg.providers.contains_key("attacker"));
        crate::config::trust::clear_runtime_policy_for_tests();
    }

    fn drift() -> Vec<(String, Vec<String>)> {
        vec![("provider".to_string(), vec!["stale-model".to_string()])]
    }

    fn model(id: &str) -> crate::config::providers::ModelEntry {
        serde_json::from_value(serde_json::json!({ "id": id })).unwrap()
    }

    #[test]
    fn noninteractive_drift_keeps_without_reading_stdin_or_persisting() {
        let mut cfg = ProvidersConfig {
            on_unlisted_models_fetch: Some(OnUnlistedModelsFetch::Ask),
            ..ProvidersConfig::default()
        };
        let mut input = Cursor::new(b"2\n".to_vec());
        let mut output = Vec::new();
        let mut notice = Vec::new();

        let decision = pick_policy_with_io(
            &mut cfg,
            None,
            &drift(),
            false,
            &mut input,
            &mut output,
            &mut notice,
        )
        .unwrap();

        assert_eq!(decision, OnUnlistedModelsFetch::Keep);
        assert_eq!(input.position(), 0);
        assert!(output.is_empty());
        let notice = String::from_utf8(notice).unwrap();
        assert!(notice.contains("Noninteractive"));
        assert!(notice.contains("--on-unlisted keep"));
        assert!(notice.contains("--on-unlisted remove"));
        assert_eq!(
            cfg.on_unlisted_models_fetch,
            Some(OnUnlistedModelsFetch::Ask)
        );
    }

    #[test]
    fn explicit_policy_bypasses_noninteractive_prompt() {
        let mut cfg = ProvidersConfig::default();
        let mut input = Cursor::new(b"1\n".to_vec());
        let mut output = Vec::new();
        let mut notice = Vec::new();

        let decision = pick_policy_with_io(
            &mut cfg,
            Some(OnUnlistedModelsFetch::Remove),
            &drift(),
            false,
            &mut input,
            &mut output,
            &mut notice,
        )
        .unwrap();

        assert_eq!(decision, OnUnlistedModelsFetch::Remove);
        assert_eq!(input.position(), 0);
        assert!(output.is_empty());
        assert!(notice.is_empty());
    }

    #[test]
    fn interactive_drift_prompt_still_reads_choice() {
        let mut cfg = ProvidersConfig::default();
        let mut input = Cursor::new(b"2\n".to_vec());
        let mut output = Vec::new();
        let mut notice = Vec::new();

        let decision = pick_policy_with_io(
            &mut cfg,
            None,
            &drift(),
            true,
            &mut input,
            &mut output,
            &mut notice,
        )
        .unwrap();

        assert_eq!(decision, OnUnlistedModelsFetch::Remove);
        assert!(String::from_utf8(output).unwrap().contains("Choose 1/2/3"));
        assert!(notice.is_empty());
    }

    #[test]
    fn interactive_dont_ask_again_persists_keep() {
        let mut cfg = ProvidersConfig::default();
        let mut input = Cursor::new(b"3\n".to_vec());
        let mut output = Vec::new();
        let mut notice = Vec::new();

        let decision = pick_policy_with_io(
            &mut cfg,
            None,
            &drift(),
            true,
            &mut input,
            &mut output,
            &mut notice,
        )
        .unwrap();

        assert_eq!(decision, OnUnlistedModelsFetch::Keep);
        assert_eq!(
            cfg.on_unlisted_models_fetch,
            Some(OnUnlistedModelsFetch::Keep)
        );
    }

    #[test]
    fn interactive_fallback_prompt_maps_choices() {
        for (input_bytes, expected) in [
            (b"1\n".as_slice(), FallbackDecision::Retry),
            (b"\n".as_slice(), FallbackDecision::Keep),
            (b"3\n".as_slice(), FallbackDecision::UseFallback),
            (b"4\n".as_slice(), FallbackDecision::Cancel),
        ] {
            let mut input = Cursor::new(input_bytes.to_vec());
            let mut output = Vec::new();

            let decision = pick_fallback_decision_with_io(
                "codex-oauth",
                "GET /models returned 500",
                &mut input,
                &mut output,
            )
            .unwrap();

            assert_eq!(decision, expected);
            let rendered = String::from_utf8(output).unwrap();
            assert!(rendered.contains("Retry live fetch"));
            assert!(rendered.contains("Use fallback catalog"));
        }
    }

    #[test]
    fn apply_models_records_explicit_fallback_status() {
        let mut entry = ProviderEntry {
            models: vec![model("existing")],
            ..ProviderEntry::default()
        };

        apply_models(
            "codex-oauth",
            &mut entry,
            vec![model("fallback")],
            ProviderModelCatalog::CodexFallback,
            Some(
                "https://api.example.test/v1/models returned 500. Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456"
                    .to_string(),
            ),
            OnUnlistedModelsFetch::Keep,
        );

        assert_eq!(entry.model_catalog, ProviderModelCatalog::CodexFallback);
        assert_eq!(
            entry
                .models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["fallback", "existing"]
        );
        let status = entry.last_model_fetch.unwrap();
        assert_eq!(
            status.status,
            crate::config::providers::ModelFetchStatusKind::Fallback
        );
        assert_eq!(
            status.source,
            crate::config::providers::ModelFetchSource::Fallback
        );
        let reason = status.reason.unwrap();
        assert!(reason.contains("returned 500"));
        assert!(reason.contains("[redacted]"));
        assert!(!reason.contains("sk-test-token"));
    }

    #[test]
    fn apply_models_defaults_known_frontier_model_ids() {
        // Known-frontier model defaults gate on the provider's persisted
        // *template* identity (`effective_template`), not the config-map key, so
        // the entry must carry the `codex-oauth` template for `gpt-5.5` to be
        // recognized as a first-party frontier id.
        let mut entry = ProviderEntry {
            template: Some("codex-oauth".to_string()),
            mode: Some(crate::config::extended::LlmMode::Defensive),
            models: vec![model("existing")],
            ..ProviderEntry::default()
        };

        apply_models(
            "codex-oauth",
            &mut entry,
            vec![model("gpt-5.5"), model("gpt-5.5-mini")],
            ProviderModelCatalog::Live,
            None,
            OnUnlistedModelsFetch::Keep,
        );

        let mode_for = |id: &str| {
            entry
                .models
                .iter()
                .find(|m| m.id == id)
                .and_then(|m| m.mode)
        };
        assert_eq!(
            mode_for("gpt-5.5"),
            Some(crate::config::extended::LlmMode::Frontier)
        );
        assert_eq!(mode_for("gpt-5.5-mini"), None);
        assert_eq!(mode_for("existing"), None);
    }

    #[test]
    fn fallback_not_accepted_keeps_existing_catalog_and_records_failure() {
        let mut entry = ProviderEntry {
            models: vec![model("existing")],
            model_catalog: ProviderModelCatalog::Live,
            ..ProviderEntry::default()
        };

        entry.mark_model_fetch_failed_kept_existing(
            "https://chatgpt.com/backend-api/codex/models?client_version=0.0.0 returned an empty model list (status 200 OK)",
        );

        assert_eq!(entry.model_catalog, ProviderModelCatalog::Live);
        assert_eq!(
            entry
                .models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["existing"]
        );
        let status = entry.last_model_fetch.unwrap();
        assert_eq!(
            status.status,
            crate::config::providers::ModelFetchStatusKind::FailedKeptExisting
        );
        assert_eq!(
            status.source,
            crate::config::providers::ModelFetchSource::Live
        );
        assert!(
            status
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("empty model list"))
        );
    }

    #[test]
    fn allow_fallback_empty_codex_message_names_empty_list() {
        let outcome = Ok(FetchOutcome::FallbackAvailable {
            models: vec![model("gpt-5.5"), model("gpt-5.4"), model("gpt-5.4-mini")],
            catalog: ProviderModelCatalog::CodexFallback,
            reason: "https://chatgpt.com/backend-api/codex/models?client_version=0.0.0 returned an empty model list (status 200 OK)".to_string(),
        });

        let line = fetch_outcome_line(&outcome, true);

        assert!(line.contains("live fetch returned an empty model list"));
        assert!(line.contains("activating fallback catalog with 3 model(s)"));
        assert!(line.contains("status 200 OK"));
    }

    #[test]
    fn fetch_status_summary_counts_each_display_state() {
        let status = |kind| crate::config::providers::ModelFetchStatus {
            status: kind,
            at: chrono::DateTime::parse_from_rfc3339("2026-06-19T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            source: crate::config::providers::ModelFetchSource::Live,
            reason: None,
        };
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "auth".to_string(),
            ProviderEntry {
                last_model_fetch: Some(status(
                    crate::config::providers::ModelFetchStatusKind::AuthFailed,
                )),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "fallback".to_string(),
            ProviderEntry {
                model_catalog: ProviderModelCatalog::CodexFallback,
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "failed".to_string(),
            ProviderEntry {
                last_model_fetch: Some(status(
                    crate::config::providers::ModelFetchStatusKind::FailedKeptExisting,
                )),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "live".to_string(),
            ProviderEntry {
                last_model_fetch: Some(status(
                    crate::config::providers::ModelFetchStatusKind::Live,
                )),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "preserved".to_string(),
            ProviderEntry {
                models: vec![model("kept")],
                last_model_fetch: Some(status(
                    crate::config::providers::ModelFetchStatusKind::FailedKeptExisting,
                )),
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "unsupported".to_string(),
            ProviderEntry {
                last_model_fetch: Some(status(
                    crate::config::providers::ModelFetchStatusKind::Unsupported,
                )),
                ..ProviderEntry::default()
            },
        );
        let targets = vec![
            "auth".to_string(),
            "fallback".to_string(),
            "failed".to_string(),
            "live".to_string(),
            "preserved".to_string(),
            "unsupported".to_string(),
        ];

        let out = fetch_status_summary(&cfg, &targets);

        assert!(out.contains("total providers: 6"));
        assert!(out.contains("Live:         1"));
        assert!(out.contains("Fallback:     1 (fallback)"));
        assert!(out.contains("Preserved:    1 (preserved)"));
        assert!(out.contains("Failed:       1 (failed)"));
        assert!(out.contains("AuthFailed:   1 (auth)"));
        assert!(out.contains("Unsupported:  1 (unsupported)"));
    }

    #[test]
    fn nous_research_model_fetch_is_explicitly_unsupported() {
        let nous = crate::providers::template_by_id("nous-research").expect("template");
        assert!(!nous.supports_models_endpoint);

        // Stock id
        let mut entry = ProviderEntry {
            template: Some("nous-research".into()),
            url: nous.url.into(),
            models: vec![crate::config::providers::ModelEntry {
                id: "Hermes-4.3-36B".into(),
                manual: true,
                ..Default::default()
            }],
            models_fetched_at: Some(chrono::Utc::now()),
            last_model_fetch: Some(crate::config::providers::ModelFetchStatus {
                status: crate::config::providers::ModelFetchStatusKind::Live,
                at: chrono::Utc::now(),
                source: crate::config::providers::ModelFetchSource::Live,
                reason: None,
            }),
            ..ProviderEntry::default()
        };
        let before = serde_json::to_vec(&entry).unwrap();
        let template = template_without_models_endpoint("nous-research", &entry).expect("skip");
        let msg = models_endpoint_unsupported_message("nous-research", template);
        assert_eq!(
            msg,
            "Provider `nous-research` (Nous Research) has no published /models endpoint. Configure models with `cockpit provider add nous-research` or `/setup model`."
        );
        assert_eq!(serde_json::to_vec(&entry).unwrap(), before);

        // Renamed map key still uses effective template
        entry.template = Some("nous-research".into());
        let template = template_without_models_endpoint("work-nous", &entry).expect("skip renamed");
        let msg = models_endpoint_unsupported_message("work-nous", template);
        assert!(msg.starts_with("Provider `work-nous` (Nous Research)"));
        assert!(msg.contains("cockpit provider add nous-research"));

        // Non-template id does not skip
        let plain = ProviderEntry {
            url: "https://api.openai.com/v1".into(),
            ..ProviderEntry::default()
        };
        assert!(template_without_models_endpoint("openai", &plain).is_none());

        // Mixed-provider order: Nous skip does not clear other targets from list
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert("a-openai".into(), plain);
        cfg.providers.insert(
            "b-nous".into(),
            ProviderEntry {
                template: Some("nous-research".into()),
                url: nous.url.into(),
                models: vec![crate::config::providers::ModelEntry {
                    id: "Hermes-4.3-36B".into(),
                    manual: true,
                    ..Default::default()
                }],
                ..ProviderEntry::default()
            },
        );
        let keys: Vec<_> = cfg.providers.keys().cloned().collect();
        assert_eq!(keys, vec!["a-openai".to_string(), "b-nous".to_string()]);
        let nous_entry = cfg.providers.get("b-nous").unwrap();
        let before_mixed = serde_json::to_vec(nous_entry).unwrap();
        assert!(template_without_models_endpoint("b-nous", nous_entry).is_some());
        assert!(
            template_without_models_endpoint("a-openai", cfg.providers.get("a-openai").unwrap())
                .is_none()
        );
        assert_eq!(
            serde_json::to_vec(cfg.providers.get("b-nous").unwrap()).unwrap(),
            before_mixed
        );
    }
}
