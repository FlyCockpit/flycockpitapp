//! Global-only external provider authentication command.
//!
//! The executable owns every ToS-sensitive login and refresh detail. Cockpit
//! only resolves its argv, executes it without a shell through the bounded
//! command runner, validates the JSON result, and stores the credential under
//! the provider id in `CredentialStore`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::credentials::CredentialStore;
use crate::secret_command::{
    CommandSecretExecutor, SubprocessCommandExecutor,
};

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct CommandCredential {
    pub token: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub headers: Option<BTreeMap<String, String>>,
}

impl CommandCredential {
    fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(!self.token.is_empty(), "auth command returned an empty token");
        Ok(())
    }
}

impl std::fmt::Debug for CommandCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CommandCredential")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field(
                "header_names",
                &self.headers.as_ref().map(|headers| headers.keys().collect::<Vec<_>>()),
            )
            .finish()
    }
}

pub(crate) async fn resolve(
    provider_id: &str,
    command: &[String],
    store: CredentialStore,
    env_lookup: &dyn Fn(&str) -> Option<String>,
    force_refresh: bool,
) -> Result<CommandCredential> {
    resolve_with_executor(
        provider_id,
        command,
        store,
        env_lookup,
        force_refresh,
        Arc::new(SubprocessCommandExecutor),
    )
    .await
}

async fn resolve_with_executor(
    provider_id: &str,
    command: &[String],
    store: CredentialStore,
    env_lookup: &dyn Fn(&str) -> Option<String>,
    force_refresh: bool,
    executor: Arc<dyn CommandSecretExecutor>,
) -> Result<CommandCredential> {
    let argv = resolve_argv(command, &store, env_lookup)?;
    let key = provider_id.to_string();
    let prior_token = load_cached(&store, &key)?.map(|credential| credential.token);
    crate::auth::refresh_guard::serialized_refresh(&key, move || async move {
        let current = store.reopen()?;
        if let Some(credential) = load_cached(&current, &key)? {
            let another_waiter_refreshed =
                force_refresh && prior_token.as_deref() != Some(credential.token.as_str());
            if another_waiter_refreshed
                || (!force_refresh && !credential.is_expired(unix_now()))
            {
                return Ok(credential);
            }
        }

        let stdout = executor
            .run(&argv)
            .await
            .map_err(|error| anyhow::anyhow!("auth command failed: {}", error.code()))?;
        let credential: CommandCredential = serde_json::from_str(&stdout)
            .context("auth command returned malformed JSON")?;
        credential.validate()?;
        current.save_record_merged(
            &key,
            serde_json::json!({ "auth_command": credential }),
        )?;
        Ok(credential)
    })
    .await
}

fn load_cached(store: &CredentialStore, provider_id: &str) -> Result<Option<CommandCredential>> {
    store.get(provider_id)
        .and_then(|record| record.get("auth_command"))
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .context("cached auth-command credential is malformed")
}

fn resolve_argv(
    command: &[String],
    store: &CredentialStore,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<Vec<String>> {
    anyhow::ensure!(!command.is_empty(), "auth_command is empty");
    let mut argv = Vec::with_capacity(command.len());
    let mut missing = Vec::new();
    let mut errors = Vec::new();
    for item in command {
        let resolved = crate::envref::resolve_with_sources(
            item,
            env_lookup,
            |name| store.named_secret(name).map(str::to_string),
        );
        missing.extend(resolved.missing);
        errors.extend(resolved.errors);
        argv.push(resolved.value);
    }
    anyhow::ensure!(errors.is_empty(), "auth_command contains invalid references");
    anyhow::ensure!(
        missing.is_empty(),
        "auth_command references missing environment variable(s) or named secret(s): {}",
        missing.join(", ")
    );
    anyhow::ensure!(
        argv.first().is_some_and(|program| !program.is_empty()),
        "auth_command executable resolved empty"
    );
    Ok(argv)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::secret_command::CommandSecretError;

    struct FakeExecutor {
        calls: AtomicUsize,
        results: Mutex<VecDeque<Result<String, CommandSecretError>>>,
    }

    impl FakeExecutor {
        fn new(results: impl IntoIterator<Item = Result<String, CommandSecretError>>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                results: Mutex::new(results.into_iter().collect()),
            })
        }
    }

    #[async_trait::async_trait]
    impl CommandSecretExecutor for FakeExecutor {
        async fn run(&self, _argv: &[String]) -> Result<String, CommandSecretError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            self.results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(r#"{"token":"unexpected-extra-call"}"#.into()))
        }
    }

    fn store() -> (tempfile::TempDir, CredentialStore) {
        let temp = tempfile::tempdir().unwrap();
        let store = CredentialStore::open(temp.path().join("credentials.json")).unwrap();
        (temp, store)
    }

    #[tokio::test]
    async fn valid_json_is_cached_under_provider_record() {
        let (_temp, store) = store();
        let executor = FakeExecutor::new([Ok(
            r#"{"token":"fresh-token","expires_at":null,"headers":{"X-Tenant":"one"}}"#
                .into(),
        )]);
        let credential = resolve_with_executor(
            "custom",
            &["auth-helper".into()],
            store.clone(),
            &|_| None,
            false,
            executor.clone(),
        )
        .await
        .unwrap();

        assert_eq!(credential.token, "fresh-token");
        assert_eq!(
            store.reopen().unwrap().get("custom").unwrap()["auth_command"]["token"],
            "fresh-token"
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn malformed_json_and_nonzero_exit_fail_closed() {
        let (_temp, store) = store();
        let malformed = FakeExecutor::new([Ok("not-json".into())]);
        let error = resolve_with_executor(
            "malformed",
            &["auth-helper".into()],
            store.clone(),
            &|_| None,
            false,
            malformed,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("malformed JSON"));

        let failed = FakeExecutor::new([Err(CommandSecretError::NonZeroExit {
            code: Some(7),
            stderr_excerpt: "rejected".into(),
        })]);
        let error = resolve_with_executor(
            "failed",
            &["auth-helper".into()],
            store,
            &|_| None,
            false,
            failed,
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), "auth command failed: non_zero_exit");
    }

    #[tokio::test]
    async fn expired_credential_refresh_is_single_flight_and_reused() {
        let (_temp, mut store) = store();
        store.set(
            "custom",
            serde_json::json!({
                "auth_command": { "token": "expired", "expires_at": 1, "headers": null }
            }),
        );
        store.save().unwrap();
        let executor = FakeExecutor::new([Ok(format!(
            r#"{{"token":"refreshed","expires_at":{},"headers":null}}"#,
            unix_now() + 3600
        ))]);

        let run = || {
            let executor = executor.clone();
            let store = store.clone();
            async move {
                resolve_with_executor(
                    "custom",
                    &["auth-helper".into()],
                    store,
                    &|_| None,
                    false,
                    executor,
                )
                .await
            }
        };
        let (first, second) = tokio::join!(run(), run());

        assert_eq!(first.unwrap().token, "refreshed");
        assert_eq!(second.unwrap().token, "refreshed");
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_forced_refresh_reuses_the_winning_refresh() {
        let (_temp, mut store) = store();
        store.set(
            "custom-401",
            serde_json::json!({
                "auth_command": { "token": "rejected", "expires_at": null, "headers": null }
            }),
        );
        store.save().unwrap();
        let executor = FakeExecutor::new([Ok(
            r#"{"token":"after-401","expires_at":null,"headers":null}"#.into(),
        )]);

        let run = || {
            let executor = executor.clone();
            let store = store.clone();
            async move {
                resolve_with_executor(
                    "custom-401",
                    &["auth-helper".into()],
                    store,
                    &|_| None,
                    true,
                    executor,
                )
                .await
            }
        };
        let (first, second) = tokio::join!(run(), run());

        assert_eq!(first.unwrap().token, "after-401");
        assert_eq!(second.unwrap().token, "after-401");
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }
}
