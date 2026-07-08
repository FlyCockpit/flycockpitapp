use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::cli::{ModelsArgs, ProviderCatalogStatusArgs};
use crate::config::providers::{
    ProviderEntry, ProvidersConfig, WireApi, format_model_fetch_age,
    provider_model_fetch_display_state, provider_model_fetch_reason_display,
};

pub async fn run(args: ModelsArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("getting cwd")?;
    let cfg = crate::config::providers::ConfigDoc::load_effective(&cwd);
    if cfg.providers.is_empty() {
        println!("{}", no_models_message());
        return Ok(());
    }
    print!("{}", render_models(&cfg, args.provider.as_deref())?);
    Ok(())
}

pub async fn run_provider_catalog_status(args: ProviderCatalogStatusArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("getting cwd")?;
    let cfg = crate::config::providers::ConfigDoc::load_effective(&cwd);
    print!(
        "{}",
        render_provider_catalog_status(&cfg, args.provider.as_deref(), Utc::now())?
    );
    Ok(())
}

fn render_models(cfg: &ProvidersConfig, provider_filter: Option<&str>) -> Result<String> {
    let providers: Vec<(&String, &ProviderEntry)> = if let Some(provider) = provider_filter {
        let Some(entry) = cfg.providers.get(provider) else {
            anyhow::bail!("no provider with id `{provider}`");
        };
        vec![(
            cfg.providers
                .get_key_value(provider)
                .map(|(id, _)| id)
                .expect("entry came from map"),
            entry,
        )]
    } else {
        cfg.providers
            .iter()
            .filter(|(_, entry)| !entry.models.is_empty())
            .collect()
    };

    if providers.is_empty() {
        return Ok(format!("{}\n", no_models_message()));
    }

    let mut out = String::new();
    for (idx, (id, entry)) in providers.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        if provider_filter.is_some() && entry.models.is_empty() {
            out.push_str(&format!(
                "provider `{id}` has no models configured\n{}\n",
                no_models_next_action()
            ));
            continue;
        }
        render_provider(&mut out, id, entry, cfg);
    }
    Ok(out)
}

fn render_provider(out: &mut String, id: &str, entry: &ProviderEntry, cfg: &ProvidersConfig) {
    out.push_str(id);
    if let Some(name) = entry.name.as_deref()
        && name != id
    {
        out.push_str(" (");
        out.push_str(name);
        out.push(')');
    }
    if entry.favorite.unwrap_or(false) {
        out.push_str(" [favorite]");
    }
    if let Some(fetched_at) = entry.models_fetched_at {
        out.push_str(" fetched=");
        out.push_str(&fetched_at.to_rfc3339());
    }
    out.push('\n');

    for model in &entry.models {
        out.push_str("  ");
        out.push_str(&model.id);
        if let Some(name) = model.name.as_deref()
            && name != model.id
        {
            out.push_str(" - ");
            out.push_str(name);
        }

        let mut markers = Vec::new();
        markers.push(if model.manual { "manual" } else { "fetched" });
        if model.favorite {
            markers.push("favorite");
        }
        if is_active_model(cfg, id, &model.id) {
            markers.push("default");
        }
        if !model.wire_api.is_auto() {
            markers.push(wire_api_label(model.wire_api));
        }
        if !markers.is_empty() {
            out.push_str(" [");
            out.push_str(&markers.join(", "));
            out.push(']');
        }
        out.push('\n');
    }
}

pub(crate) fn render_provider_catalog_status(
    cfg: &ProvidersConfig,
    provider_filter: Option<&str>,
    now: DateTime<Utc>,
) -> Result<String> {
    if cfg.providers.is_empty() {
        return Ok("no providers configured\n".to_string());
    }

    let providers: Vec<(&String, &ProviderEntry)> = if let Some(provider) = provider_filter {
        let Some(entry) = cfg.providers.get(provider) else {
            anyhow::bail!("no provider with id `{provider}`");
        };
        vec![(
            cfg.providers
                .get_key_value(provider)
                .map(|(id, _)| id)
                .expect("entry came from map"),
            entry,
        )]
    } else {
        cfg.providers.iter().collect()
    };

    let mut out = String::new();
    for (idx, (id, entry)) in providers.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        render_provider_catalog_status_block(&mut out, id, entry, now);
    }
    Ok(out)
}

pub(crate) fn render_provider_catalog_status_block(
    out: &mut String,
    id: &str,
    entry: &ProviderEntry,
    now: DateTime<Utc>,
) {
    let state = provider_model_fetch_display_state(entry).label();
    out.push_str(id);
    if let Some(name) = entry.name.as_deref()
        && name != id
    {
        out.push_str(" (");
        out.push_str(name);
        out.push(')');
    }
    out.push('\n');
    out.push_str(&format!("  state:   {state}\n"));
    out.push_str(&format!("  count:   {}\n", entry.models.len()));
    out.push_str(&format!(
        "  fetched: {}\n",
        format_model_fetch_age(entry.models_fetched_at, now)
    ));
    out.push_str(&format!(
        "  reason:  {}\n",
        provider_model_fetch_reason_display(entry)
    ));
}

fn is_active_model(cfg: &ProvidersConfig, provider: &str, model: &str) -> bool {
    cfg.active_model
        .as_ref()
        .map(|active| active.provider == provider && active.model == model)
        .unwrap_or(false)
}

fn wire_api_label(wire_api: WireApi) -> &'static str {
    match wire_api {
        WireApi::Auto => "wire=auto",
        WireApi::Completions => "wire=completions",
        WireApi::Responses => "wire=responses",
    }
}

fn no_models_message() -> &'static str {
    "no models configured\nnext: run `cockpit fetch-models` or open provider settings"
}

fn no_models_next_action() -> &'static str {
    "next: run `cockpit fetch-models` or open provider settings"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{
        ActiveModelRef, ModelEntry, ModelFetchSource, ModelFetchStatus, ModelFetchStatusKind,
        ProviderModelCatalog, ThinkingMode,
    };

    fn cfg_from_json(json: &str) -> ProvidersConfig {
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        let raw = value.as_object().unwrap();
        let mut cfg = ProvidersConfig::default();
        if let Some(providers) = raw.get("providers").and_then(serde_json::Value::as_object) {
            for (id, entry) in providers {
                cfg.providers.insert(
                    id.clone(),
                    serde_json::from_value::<ProviderEntry>(entry.clone()).unwrap(),
                );
            }
        }
        if let Some(active) = raw.get("active_model") {
            cfg.active_model = Some(serde_json::from_value(active.clone()).unwrap());
        }
        cfg
    }

    #[test]
    fn no_providers_or_models_prints_next_action() {
        let cfg = ProvidersConfig::default();
        let out = render_models(&cfg, None).unwrap();

        assert!(out.contains("no models configured"));
        assert!(out.contains("cockpit fetch-models"));
    }

    #[test]
    fn all_providers_are_grouped_and_skip_empty_providers() {
        let cfg = cfg_from_json(
            r#"{
                "providers": {
                    "empty": { "url": "https://empty.example", "models": [] },
                    "openai": {
                        "name": "OpenAI",
                        "url": "https://api.openai.com/v1",
                        "models": [
                            { "id": "gpt-5-mini", "name": "GPT-5 Mini" }
                        ]
                    },
                    "local": {
                        "url": "http://localhost:11434/v1",
                        "models": [
                            { "id": "llama", "manual": true }
                        ]
                    }
                }
            }"#,
        );

        let out = render_models(&cfg, None).unwrap();

        assert!(out.contains("openai (OpenAI)"));
        assert!(out.contains("  gpt-5-mini - GPT-5 Mini [fetched]"));
        assert!(out.contains("local"));
        assert!(out.contains("  llama [manual]"));
        assert!(!out.contains("empty"));
    }

    #[test]
    fn provider_filter_lists_only_that_provider() {
        let cfg = cfg_from_json(
            r#"{
                "providers": {
                    "openai": {
                        "url": "https://api.openai.com/v1",
                        "models": [{ "id": "gpt-5-mini" }]
                    },
                    "local": {
                        "url": "http://localhost:11434/v1",
                        "models": [{ "id": "llama", "manual": true }]
                    }
                }
            }"#,
        );

        let out = render_models(&cfg, Some("local")).unwrap();

        assert!(out.contains("local"));
        assert!(out.contains("llama"));
        assert!(!out.contains("openai"));
    }

    #[test]
    fn markers_cover_manual_fetched_favorite_default_and_wire() {
        let mut cfg = cfg_from_json(
            r#"{
                "providers": {
                    "openai": {
                        "url": "https://api.openai.com/v1",
                        "models": [
                            { "id": "gpt-5-mini", "favorite": true, "wire_api": "responses" },
                            { "id": "custom", "manual": true, "wire_api": "completions" }
                        ]
                    }
                }
            }"#,
        );
        cfg.active_model = Some(ActiveModelRef {
            provider: "openai".to_string(),
            model: "gpt-5-mini".to_string(),
            reasoning_effort: None,
            thinking_mode: Some(ThinkingMode::High),
        });

        let out = render_models(&cfg, Some("openai")).unwrap();

        assert!(out.contains("gpt-5-mini [fetched, favorite, default, wire=responses]"));
        assert!(out.contains("custom [manual, wire=completions]"));
    }

    #[test]
    fn unknown_provider_errors() {
        let cfg = cfg_from_json(
            r#"{
                "providers": {
                    "openai": {
                        "url": "https://api.openai.com/v1",
                        "models": [{ "id": "gpt-5-mini" }]
                    }
                }
            }"#,
        );

        let err = render_models(&cfg, Some("missing"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no provider with id `missing`"));
    }

    #[test]
    fn provider_filter_with_no_models_prints_targeted_next_action() {
        let cfg = cfg_from_json(
            r#"{
                "providers": {
                    "empty": { "url": "https://empty.example", "models": [] }
                }
            }"#,
        );

        let out = render_models(&cfg, Some("empty")).unwrap();

        assert!(out.contains("provider `empty` has no models configured"));
        assert!(out.contains("cockpit fetch-models"));
    }

    #[test]
    fn provider_catalog_status_lists_all_providers_in_order() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "fallback".to_string(),
            ProviderEntry {
                model_catalog: ProviderModelCatalog::CodexFallback,
                models: vec![ModelEntry {
                    id: "gpt-5.5".to_string(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        cfg.providers.insert(
            "live".to_string(),
            ProviderEntry {
                name: Some("Live Provider".to_string()),
                models_fetched_at: Some(
                    DateTime::parse_from_rfc3339("2026-06-19T11:59:30Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
                models: vec![ModelEntry {
                    id: "gpt-5-mini".to_string(),
                    ..ModelEntry::default()
                }],
                last_model_fetch: Some(ModelFetchStatus {
                    status: ModelFetchStatusKind::Live,
                    at: DateTime::parse_from_rfc3339("2026-06-19T11:59:30Z")
                        .unwrap()
                        .with_timezone(&Utc),
                    source: ModelFetchSource::Live,
                    reason: None,
                }),
                ..ProviderEntry::default()
            },
        );
        let now = DateTime::parse_from_rfc3339("2026-06-19T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let out = render_provider_catalog_status(&cfg, None, now).unwrap();

        assert!(
            out.find("fallback\n").unwrap() < out.find("live (Live Provider)\n").unwrap(),
            "{out}"
        );
        assert!(out.contains("fallback\n  state:   Fallback"));
        assert!(out.contains("  fetched: never"));
        assert!(out.contains("live (Live Provider)\n  state:   Live"));
        assert!(out.contains("  fetched: just now"));
        assert!(out.contains("  reason:  —"));
    }

    #[test]
    fn provider_catalog_status_filter_redacts_reason_and_preserves_unknown_error() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "openai".to_string(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "gpt-5-mini".to_string(),
                    ..ModelEntry::default()
                }],
                models_fetched_at: Some(
                    DateTime::parse_from_rfc3339("2026-06-19T11:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
                last_model_fetch: Some(ModelFetchStatus {
                    status: ModelFetchStatusKind::FailedKeptExisting,
                    at: DateTime::parse_from_rfc3339("2026-06-19T11:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                    source: ModelFetchSource::Live,
                    reason: Some(
                        "GET /models returned 500 Authorization Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456"
                            .to_string(),
                    ),
                }),
                ..ProviderEntry::default()
            },
        );
        let now = DateTime::parse_from_rfc3339("2026-06-19T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let out = render_provider_catalog_status(&cfg, Some("openai"), now).unwrap();

        assert!(out.contains("state:   Preserved"));
        assert!(out.contains("1 hour ago"));
        assert!(out.contains("[redacted]"));
        assert!(!out.contains("sk-test-token"));
        let err = render_provider_catalog_status(&cfg, Some("missing"), now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no provider with id `missing`"));
    }
}
