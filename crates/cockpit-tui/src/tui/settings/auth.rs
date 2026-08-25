//! Background async work owned by the settings dialog: the `/models`
//! fetch behind the provider Save/Refetch actions.
//!
//! [`FetchHandle`] is a shared-cell wrapper: a tokio task writes into an
//! `Arc<Mutex<…>>`, the dialog's tick polls it on each event-loop
//! pass. It lives here rather than in the main dialog file because it is
//! async plumbing, not UI state.

use cockpit_config::providers::ProviderEntry;
use cockpit_core::providers::models_fetch::FetchOutcome;
use cockpit_proto::{ProviderModelFetchOutcome, Request, Response};
use std::sync::{Arc, Mutex};

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
    pub fn spawn(provider_id: String, _entry: ProviderEntry, project_root: String) -> Self {
        let state = Arc::new(Mutex::new(FetchState::Running));
        let state_w = Arc::clone(&state);
        let pid = provider_id.clone();
        tokio::spawn(async move {
            let result = async {
                let client = crate::tui::settings::settings_daemon_client()
                    .await
                    .map_err(|error| error.to_string())?;
                let response = client
                    .request(Request::FetchProviderModels {
                        project_root,
                        provider_id: Some(pid.clone()),
                        model_id: None,
                        deep: false,
                        on_unlisted: None,
                        allow_fallback: false,
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
                Ok(match outcome {
                    ProviderModelFetchOutcome::Models { models, catalog } => {
                        FetchOutcome::Models { models, catalog }
                    }
                    ProviderModelFetchOutcome::FallbackAvailable {
                        models,
                        catalog,
                        reason,
                    } => FetchOutcome::FallbackAvailable {
                        models,
                        catalog,
                        reason,
                    },
                    ProviderModelFetchOutcome::UnlistedModelsPreview { unlisted_count } => {
                        return Err(format!(
                            "model fetch needs a keep/remove decision for {unlisted_count} configured model(s)"
                        ));
                    }
                    ProviderModelFetchOutcome::Unsupported => FetchOutcome::Unsupported,
                    ProviderModelFetchOutcome::Error { message } => return Err(message),
                })
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
