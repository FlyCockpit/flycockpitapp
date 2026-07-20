use super::*;

impl App {
    /// Kick off a non-interactive cross-provider `/models` refresh.
    /// Lines land in `fetch_models_progress`; the event loop drains
    /// them into history.
    pub(super) fn spawn_fetch_models(&mut self) {
        use cockpit_config::providers::{
            ModelMergePolicy, OnUnlistedModelsFetch, merge_fetched_models_with_policy,
            redact_model_fetch_reason,
        };
        use cockpit_core::providers::models_fetch::persist_provider;
        use cockpit_core::providers::models_fetch::{self, FetchOutcome};
        use std::time::Duration;

        let cwd = self.launch.cwd.clone();
        let progress = Arc::clone(&self.fetch_models_progress);
        self.push_plain("/fetch-models: starting provider model refresh…".to_string());

        tokio::spawn(async move {
            let push = |lines: &Arc<Mutex<Vec<String>>>, s: String| {
                if let Ok(mut g) = lines.lock() {
                    g.push(s);
                }
            };

            // A `/fetch-models` refresh makes authenticated network requests
            // per provider, so it needs the full (unredacted) provider entries
            // — the daemon's redacted snapshot cannot serve it, and there is no
            // wire request for a daemon-side fetch. Load the layered provider
            // config directly (credentials are resolved at request-construction
            // time in core, not here); this is NOT `load_effective`, so no
            // credential resolution or `$secret:` migration happens in the TUI.
            let paths = cockpit_config::dirs::config_file_paths_for_load(&cwd);
            let mut cfg = cockpit_config::providers::ConfigDoc::providers_from_paths(&paths);
            let policy = cfg
                .on_unlisted_models_fetch
                .unwrap_or(OnUnlistedModelsFetch::Keep);

            if cfg.providers.is_empty() {
                push(
                    &progress,
                    "/fetch-models: no providers configured for provider models".into(),
                );
                return;
            }

            let ids: Vec<String> = cfg.providers.keys().cloned().collect();
            for id in &ids {
                let entry = cfg.providers.get(id).cloned().unwrap();
                let resolved = match models_fetch::resolve_provider_request_async(id, &entry).await
                {
                    Ok(r) => r,
                    Err(e) => {
                        push(&progress, format!("/fetch-models: {id} skipped — {e}"));
                        continue;
                    }
                };
                match models_fetch::fetch_models_for_provider(
                    id,
                    &entry,
                    &resolved,
                    Duration::from_secs(15),
                )
                .await
                {
                    Ok(FetchOutcome::Models {
                        models: remote,
                        catalog,
                    }) => {
                        let n = remote.len();
                        let entry_mut = cfg.providers.get_mut(id).unwrap();
                        let merge_policy = match policy {
                            OnUnlistedModelsFetch::Keep => ModelMergePolicy::KeepUnlisted,
                            OnUnlistedModelsFetch::Remove | OnUnlistedModelsFetch::Ask => {
                                ModelMergePolicy::RemoveUnlisted
                            }
                        };
                        entry_mut.models = merge_fetched_models_with_policy(
                            entry_mut.effective_template(id),
                            &entry_mut.models,
                            remote,
                            merge_policy,
                        );
                        entry_mut.models_fetched_at = Some(chrono::Utc::now());
                        entry_mut.model_catalog = catalog;
                        entry_mut.mark_model_fetch_success(catalog);
                        match persist_provider(&cwd, id, entry_mut.clone()) {
                            Ok(_) => {
                                let suffix = if matches!(
                                    catalog,
                                    cockpit_config::providers::ProviderModelCatalog::CodexFallback
                                ) {
                                    " (fallback catalog)"
                                } else {
                                    ""
                                };
                                push(
                                    &progress,
                                    format!(
                                        "/fetch-models: provider {id} → {n} provider model(s){suffix}"
                                    ),
                                )
                            }
                            Err(e) => {
                                push(&progress, format!("/fetch-models: {id} write failed: {e}"))
                            }
                        }
                    }
                    Ok(FetchOutcome::FallbackAvailable { reason, .. }) => {
                        let reason = redact_model_fetch_reason(reason);
                        let entry_mut = cfg.providers.get_mut(id).unwrap();
                        entry_mut.mark_model_fetch_failed_kept_existing(reason.clone());
                        let _ = persist_provider(&cwd, id, entry_mut.clone());
                        push(
                            &progress,
                            format!(
                                "/fetch-models: provider {id} live catalog fetch failed; kept existing provider catalog; fallback available from provider settings: {reason}"
                            ),
                        );
                    }
                    Ok(FetchOutcome::Unsupported) => {
                        let entry_mut = cfg.providers.get_mut(id).unwrap();
                        entry_mut.mark_model_fetch_unsupported();
                        let _ = persist_provider(&cwd, id, entry_mut.clone());
                        push(
                            &progress,
                            format!("/fetch-models: provider {id} has no /models endpoint"),
                        );
                    }
                    Err(e) => {
                        let reason = redact_model_fetch_reason(e.to_string());
                        let entry_mut = cfg.providers.get_mut(id).unwrap();
                        entry_mut.mark_model_fetch_failed_kept_existing(reason.clone());
                        let _ = persist_provider(&cwd, id, entry_mut.clone());
                        push(
                            &progress,
                            format!("/fetch-models: provider {id} failed: {reason}"),
                        );
                    }
                }
            }

            push(
                &progress,
                "/fetch-models: provider model refresh done".into(),
            );
        });
    }
}
