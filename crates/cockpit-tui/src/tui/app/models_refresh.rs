use super::*;

impl App {
    /// Kick off a daemon-owned cross-provider `/models` refresh.  The daemon
    /// alone resolves `$secret:` references and persists the resulting model
    /// metadata; this UI only renders the safe outcome projection.
    pub(super) fn spawn_fetch_models(&mut self) {
        use cockpit_proto::{ProviderModelFetchOutcome, Request, Response};

        let cwd = self.launch.cwd.clone();
        let progress = Arc::clone(&self.fetch_models_progress);
        self.push_plain("/fetch-models: starting provider model refresh…".to_string());
        tokio::spawn(async move {
            let push = |text: String| {
                if let Ok(mut lines) = progress.lock() {
                    lines.push(text);
                }
            };
            let result = async {
                let client = crate::tui::settings::settings_daemon_client().await?;
                client
                    .request(Request::FetchProviderModels {
                        project_root: cwd.display().to_string(),
                        provider_id: None,
                        model_id: None,
                        deep: false,
                        on_unlisted: None,
                        allow_fallback: false,
                    })
                    .await?
                    .map_err(|error| {
                        anyhow::anyhow!("daemon rejected provider model refresh: {error}")
                    })
            }
            .await;
            match result {
                Ok(Response::ProviderModelsFetched { results, .. }) => {
                    if results.is_empty() {
                        push("/fetch-models: no providers configured for provider models".into());
                    }
                    for result in results {
                        match result.outcome {
                            ProviderModelFetchOutcome::Models { models, catalog } => {
                                let suffix = if matches!(
                                    catalog,
                                    cockpit_config::providers::ProviderModelCatalog::CodexFallback
                                ) {
                                    " (fallback catalog)"
                                } else {
                                    ""
                                };
                                push(format!(
                                    "/fetch-models: provider {} → {} provider model(s){suffix}",
                                    result.provider_id,
                                    models.len()
                                ));
                            }
                            ProviderModelFetchOutcome::FallbackAvailable { reason, .. } => {
                                push(format!(
                                    "/fetch-models: provider {} live catalog fetch failed; kept existing provider catalog; fallback available: {reason}",
                                    result.provider_id
                                ))
                            }
                            ProviderModelFetchOutcome::Unsupported => push(format!(
                                "/fetch-models: provider {} has no /models endpoint",
                                result.provider_id
                            )),
                            ProviderModelFetchOutcome::UnlistedModelsPreview { unlisted_count } => {
                                push(format!(
                                    "/fetch-models: provider {} has {unlisted_count} configured model(s) absent from the fetched catalog; choose keep or remove in Provider settings",
                                    result.provider_id
                                ))
                            }
                            ProviderModelFetchOutcome::Error { message } => push(format!(
                                "/fetch-models: provider {} failed: {message}",
                                result.provider_id
                            )),
                        }
                    }
                }
                Ok(other) => push(format!(
                    "/fetch-models: daemon returned unexpected response: {other:?}"
                )),
                Err(error) => push(format!("/fetch-models: {error}")),
            }
            push("/fetch-models: provider model refresh done".into());
        });
    }
}
