//! Background async work owned by the settings dialog: the `/models`
//! fetch behind the provider Save/Refetch actions.
//!
//! [`FetchHandle`] is a shared-cell wrapper: a tokio task writes into an
//! `Arc<Mutex<…>>`, the dialog's tick polls it on each event-loop
//! pass. It lives here rather than in the main dialog file because it is
//! async plumbing, not UI state.

use cockpit_config::providers::{ModelEntry, ProviderEntry, ProviderModelCatalog};
use cockpit_proto::{ProviderModelFetchOutcome, Request, Response};
use std::sync::{Arc, Mutex};

/// Settings-side result of one daemon catalog refresh.
///
/// `FetchProviderModels` answers with a bounded summary (#545): the daemon is
/// the merge/persist authority and never ships a catalog over that RPC. The
/// handle therefore re-reads the provider entry the daemon persisted and
/// hands the dialog full entries:
///
/// * `Models::models` are the persisted entries for the fetched upstream ids
///   (the daemon's merge keeps per-model overrides). When the summary's id
///   preview was truncated (very large catalogs) the whole persisted list is
///   returned instead, so no configured model is mistaken for an unlisted one.
/// * `FallbackApplied` follows a request that allowed the fallback catalog;
///   `models` is the persisted catalog.
#[derive(Debug, Clone)]
pub enum FetchOutcome {
    Models {
        models: Vec<ModelEntry>,
        catalog: ProviderModelCatalog,
        /// Non-empty when the daemon trimmed an oversized catalog; shown to
        /// the user with the fetch result.
        trim_note: String,
    },
    /// The live fetch failed and the daemon offers a fallback catalog of
    /// `fallback_count` models. Nothing was applied; the user decides.
    FallbackAvailable {
        catalog: ProviderModelCatalog,
        reason: String,
        fallback_count: u32,
    },
    FallbackApplied {
        models: Vec<ModelEntry>,
        catalog: ProviderModelCatalog,
        reason: String,
    },
    Unsupported,
}

/// Shared cell for an in-flight `/models` fetch. The background task
/// writes the result; the event loop polls it on each tick.
#[derive(Clone)]
pub struct FetchHandle {
    pub provider_id: String,
    pub state: Arc<Mutex<FetchState>>,
}

pub enum FetchState {
    Running,
    Done(Result<FetchOutcome, String>),
    /// Consumed already — left as a terminal marker so the dialog
    /// doesn't double-apply the result.
    Consumed,
}

impl FetchHandle {
    pub fn spawn(
        lifecycle: cockpit_client::LifecycleClient,
        provider_id: String,
        entry: ProviderEntry,
        project_root: String,
    ) -> Self {
        Self::spawn_with_fallback(lifecycle, provider_id, entry, project_root, false)
    }

    pub fn spawn_allowing_fallback(
        lifecycle: cockpit_client::LifecycleClient,
        provider_id: String,
        entry: ProviderEntry,
        project_root: String,
    ) -> Self {
        Self::spawn_with_fallback(lifecycle, provider_id, entry, project_root, true)
    }

    fn spawn_with_fallback(
        lifecycle: cockpit_client::LifecycleClient,
        provider_id: String,
        _entry: ProviderEntry,
        project_root: String,
        allow_fallback: bool,
    ) -> Self {
        let state = Arc::new(Mutex::new(FetchState::Running));
        let state_w = Arc::clone(&state);
        let pid = provider_id.clone();
        tokio::spawn(async move {
            let result = async {
                let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                    .await
                    .map_err(|error| error.to_string())?;
                let response = client
                    .request(Request::FetchProviderModels {
                        project_root: project_root.clone(),
                        provider_id: Some(pid.clone()),
                        model_id: None,
                        deep: false,
                        on_unlisted: None,
                        allow_fallback,
                    })
                    .await
                    .map_err(|error| error.to_string())?
                    .map_err(|error| error.to_string())?;
                let Response::ProviderModelsFetched { mut results, .. } = response else {
                    return Err(
                        "daemon returned unexpected provider model fetch response".to_string()
                    );
                };
                let outcome = results
                    .pop()
                    .ok_or_else(|| "daemon returned no provider model fetch result".to_string())?
                    .outcome;
                match outcome {
                    ProviderModelFetchOutcome::Models {
                        models,
                        catalog,
                        kept,
                    } => {
                        let persisted =
                            persisted_provider_models(&client, &project_root, &pid).await?;
                        Ok(FetchOutcome::Models {
                            trim_note: cockpit_proto::catalog_trim_note(models.count, kept),
                            models: fetched_entries(persisted, &models),
                            catalog,
                        })
                    }
                    ProviderModelFetchOutcome::FallbackAvailable {
                        models,
                        catalog,
                        reason,
                    } if allow_fallback => Ok(FetchOutcome::FallbackApplied {
                        models: fetched_entries(
                            persisted_provider_models(&client, &project_root, &pid).await?,
                            &models,
                        ),
                        catalog,
                        reason,
                    }),
                    ProviderModelFetchOutcome::FallbackAvailable {
                        models,
                        catalog,
                        reason,
                    } => Ok(FetchOutcome::FallbackAvailable {
                        catalog,
                        reason,
                        fallback_count: models.count,
                    }),
                    ProviderModelFetchOutcome::Unsupported => Ok(FetchOutcome::Unsupported),
                    ProviderModelFetchOutcome::UnlistedModelsPreview { unlisted } => Err(format!(
                        "model fetch needs a keep/remove decision for {} configured model(s)",
                        unlisted.count
                    )),
                    ProviderModelFetchOutcome::Error { message } => Err(message),
                }
            }
            .await;
            if let Ok(mut s) = state_w.lock() {
                *s = FetchState::Done(result);
            }
        });
        Self { provider_id, state }
    }

    pub fn take(&self) -> Option<Result<FetchOutcome, String>> {
        let mut s = self.state.lock().ok()?;
        match std::mem::replace(&mut *s, FetchState::Consumed) {
            FetchState::Running => {
                *s = FetchState::Running;
                None
            }
            FetchState::Done(r) => Some(r),
            FetchState::Consumed => None,
        }
    }
}

/// Read back the model entries the daemon just persisted for `provider_id`.
async fn persisted_provider_models(
    client: &cockpit_client::DaemonClient,
    project_root: &str,
    provider_id: &str,
) -> Result<Vec<ModelEntry>, String> {
    let mut config = provider_snapshot_view(client, project_root, provider_id).await?;
    config
        .providers
        .remove(provider_id)
        .map(|view| view.entry.models)
        .ok_or_else(|| format!("provider `{provider_id}` disappeared after the model fetch"))
}

/// The daemon's provider-scoped catalog snapshot: the authoritative entry
/// after a catalog refresh the daemon persisted.
async fn provider_snapshot_view(
    client: &cockpit_client::DaemonClient,
    project_root: &str,
    provider_id: &str,
) -> Result<cockpit_proto::ProviderConfigView, String> {
    let response = client
        .request(Request::GetProviderCatalogSnapshot {
            project_root: project_root.to_string(),
            provider_id: Some(provider_id.to_string()),
            snapshot_session_id: uuid::Uuid::new_v4().to_string(),
        })
        .await
        .map_err(|error| format!("reading the refreshed catalog failed: {error}"))?
        .map_err(|error| format!("reading the refreshed catalog failed: {error}"))?;
    let Response::ProviderCatalogSnapshot { config, .. } = response else {
        return Err("daemon returned an unexpected provider catalog snapshot".to_string());
    };
    Ok(config)
}

/// The persisted entries that correspond to the fetched upstream ids. A
/// truncated id preview cannot separate fetched from retained models, so the
/// whole persisted list stands in for the fetched one.
fn fetched_entries(
    persisted: Vec<ModelEntry>,
    fetched: &cockpit_proto::ProviderModelIdSummary,
) -> Vec<ModelEntry> {
    if fetched.omitted() > 0 {
        return persisted;
    }
    let ids = fetched
        .ids
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    persisted
        .into_iter()
        .filter(|model| ids.contains(model.id.as_str()))
        .collect()
}
