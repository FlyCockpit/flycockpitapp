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

/// An indivisible editable read: never adopt a catalog without its baseline
/// and authority. Every refresh exit (including ambiguous transport failure)
/// reads the full snapshot so sibling providers remain in the dialog.
#[derive(Clone)]
pub(super) struct ProviderSnapshot {
    pub config: cockpit_proto::ProviderConfigView,
    pub authority: super::ProviderEditAuthority,
}

pub struct FetchCompletion {
    pub observation: FetchObservation,
    pub(super) snapshot: Result<ProviderSnapshot, String>,
}

/// The fetch observation survives independently of read-back authority. In
/// particular, never turn a real rejection into a snapshot/transport error.
/// Successful catalogs are materialized only from an adopted complete snapshot,
/// not from a possibly truncated wire summary or a pre-fetch model bag.
pub struct FetchObservation {
    pub(super) provider_id: String,
    response: Result<cockpit_proto::ProviderModelFetchResult, String>,
    allow_fallback: bool,
}

impl FetchObservation {
    pub(super) fn into_outcome(
        self,
        config: &cockpit_config::providers::ProvidersConfig,
    ) -> Result<FetchOutcome, String> {
        let result = self.response?;
        let persisted = || {
            config
                .providers
                .get(&self.provider_id)
                .map(|entry| entry.models.clone())
                .ok_or_else(|| {
                    format!(
                        "provider `{}` disappeared after the model fetch",
                        self.provider_id
                    )
                })
        };
        match result.outcome {
            ProviderModelFetchOutcome::Models {
                models,
                catalog,
                kept,
            } => Ok(FetchOutcome::Models {
                models: persisted()?,
                catalog,
                trim_note: cockpit_proto::catalog_trim_note(models.count, kept),
            }),
            ProviderModelFetchOutcome::FallbackAvailable {
                catalog, reason, ..
            } if self.allow_fallback => Ok(FetchOutcome::FallbackApplied {
                models: persisted()?,
                catalog,
                reason,
            }),
            ProviderModelFetchOutcome::FallbackAvailable {
                models,
                catalog,
                reason,
            } => Ok(FetchOutcome::FallbackAvailable {
                fallback_count: models.count,
                catalog,
                reason,
            }),
            ProviderModelFetchOutcome::Unsupported => Ok(FetchOutcome::Unsupported),
            ProviderModelFetchOutcome::UnlistedModelsPreview { unlisted } => Err(format!(
                "model fetch needs a keep/remove decision for {} configured model(s)",
                unlisted.count
            )),
            ProviderModelFetchOutcome::Error { message } => Ok(FetchOutcome::Failed {
                reason: message,
                failure: match result.verification {
                    Some(cockpit_proto::ProviderModelVerification::Unauthorized {
                        status: 401 | 403,
                    }) => cockpit_config::providers::ModelFetchFailure::CredentialsRejected,
                    _ => cockpit_config::providers::ModelFetchFailure::Other,
                },
            }),
        }
    }
}

/// Settings-side result of one daemon catalog refresh.
///
/// The fetch RPC returns a summary; the background task also reads a full
/// authoritative snapshot. `Models::models` and `FallbackApplied::models`
/// contain the complete persisted provider catalog, including retained manual
/// and favorite entries. The dialog adopts its matching authority and baseline
/// before applying UI status. No consumer reconstructs a pre-fetch model bag.
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
    /// The daemon observed a failed fetch. Keep its category beside the
    /// scrubbed display text through settings/onboarding persistence.
    Failed {
        reason: String,
        failure: cockpit_config::providers::ModelFetchFailure,
    },
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
    Done(FetchCompletion),
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
            let completion = match crate::tui::settings::settings_daemon_client(&lifecycle).await {
                Err(error) => FetchCompletion {
                    observation: FetchObservation {
                        provider_id: pid.clone(),
                        response: Err(error.to_string()),
                        allow_fallback,
                    },
                    snapshot: Err(error.to_string()),
                },
                Ok(client) => {
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
                        .map_err(|error| error.to_string())
                        .and_then(|result| result.map_err(|error| error.to_string()));
                    // A lost reply can follow a commit. Always read back, even
                    // when the very first request returned a transport error.
                    let snapshot = provider_snapshot(&client, &project_root).await;
                    let response = response.and_then(|response| {
                        let Response::ProviderModelsFetched { mut results, .. } = response else {
                            return Err(
                                "daemon returned unexpected provider model fetch response".into()
                            );
                        };
                        if results.len() != 1 || results[0].provider_id != pid {
                            return Err(
                                "daemon returned mismatched provider model fetch results".into()
                            );
                        }
                        Ok(results.remove(0))
                    });
                    FetchCompletion {
                        observation: FetchObservation {
                            provider_id: pid,
                            response,
                            allow_fallback,
                        },
                        snapshot,
                    }
                }
            };
            if let Ok(mut s) = state_w.lock() {
                *s = FetchState::Done(completion);
            }
        });
        Self { provider_id, state }
    }

    pub fn take(&self) -> Option<FetchCompletion> {
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

/// Reconcile after every potentially committed request. The full config,
/// capability, revision and generation are returned as one value.
pub(super) async fn provider_snapshot(
    client: &cockpit_client::DaemonClient,
    project_root: &str,
) -> Result<ProviderSnapshot, String> {
    let requested_id = uuid::Uuid::new_v4().to_string();
    let response = client
        .request(Request::GetProviderCatalogSnapshot {
            project_root: project_root.to_string(),
            provider_id: None,
            snapshot_session_id: requested_id.clone(),
        })
        .await
        .map_err(|error| format!("reading the refreshed catalog failed: {error}"))?
        .map_err(|error| format!("reading the refreshed catalog failed: {error}"))?;
    snapshot_from_response(response, Some(&requested_id))
}

pub(super) fn snapshot_from_response(
    response: Response,
    expected_id: Option<&str>,
) -> Result<ProviderSnapshot, String> {
    match response {
        Response::ProviderCatalogSnapshot {
            config,
            snapshot_session_id,
            layer_id,
            owner_root,
            base_revision,
            config_generation,
        } if expected_id.is_none_or(|id| id == snapshot_session_id) => Ok(ProviderSnapshot {
            config,
            authority: super::ProviderEditAuthority {
                snapshot_session_id,
                layer_id,
                owner_root,
                base_revision,
                config_generation,
            },
        }),
        _ => Err("daemon returned an unexpected provider catalog snapshot".into()),
    }
}
