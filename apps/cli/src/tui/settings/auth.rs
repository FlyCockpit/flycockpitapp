//! Background async work owned by the settings dialog: the `/models`
//! fetch behind the provider Save/Refetch actions.
//!
//! [`FetchHandle`] is a shared-cell wrapper: a tokio task writes into an
//! `Arc<Mutex<…>>`, the dialog's tick polls it on each event-loop
//! pass. It lives here rather than in the main dialog file because it is
//! async plumbing, not UI state.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::providers::ProviderEntry;
use crate::providers::models_fetch::{self, FetchOutcome};

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
    pub fn spawn(provider_id: String, entry: ProviderEntry) -> Self {
        let state = Arc::new(Mutex::new(FetchState::Running));
        let state_w = Arc::clone(&state);
        let pid = provider_id.clone();
        tokio::spawn(async move {
            let result = match models_fetch::resolve_provider_request_async(&pid, &entry).await {
                Err(e) => Err(e.to_string()),
                Ok(r) => models_fetch::fetch_models_for_provider(
                    &pid,
                    &entry,
                    &r,
                    Some(Duration::from_secs(15)),
                )
                .await
                .map_err(|e| e.to_string()),
            };
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
