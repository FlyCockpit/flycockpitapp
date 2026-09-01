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
use sha2::{Digest, Sha256};

use crate::credentials::CredentialStore;
use crate::secret_command::{CommandSecretExecutor, SubprocessCommandExecutor};

#[derive(Debug)]
struct RefreshFailure {
    source: anyhow::Error,
}

impl std::fmt::Display for RefreshFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("provider auth command refresh failed")
    }
}

impl std::error::Error for RefreshFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(crate) fn refresh_failure(source: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(RefreshFailure { source })
}

pub(crate) fn is_refresh_failure(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<RefreshFailure>().is_some())
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct CommandCredential {
    pub token: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub headers: Option<BTreeMap<String, String>>,
    /// The monotonically increasing generation of this cached command result.
    /// This is process-local request metadata, never part of the command JSON
    /// contract or persisted credential payload.
    #[serde(skip)]
    pub(crate) refresh_generation: u64,
}

/// The persisted command result is bound to the fully resolved argv and the
/// complete provider configuration that will use it. Storing only the digest
/// avoids putting resolved `$secret:`/environment values in the credential
/// record.
#[derive(Clone, Deserialize, Serialize)]
struct CachedCommandCredential {
    configuration_identity: String,
    refresh_generation: u64,
    credential: CommandCredential,
}

impl CommandCredential {
    fn is_expired(&self, now: i64) -> bool {
        self.expires_at.is_some_and(|expires_at| expires_at <= now)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.token.is_empty(),
            "auth command returned an empty token"
        );
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
                &self
                    .headers
                    .as_ref()
                    .map(|headers| headers.keys().collect::<Vec<_>>()),
            )
            .finish()
    }
}

pub(crate) async fn resolve(
    provider_id: &str,
    entry: &cockpit_config::config::providers::ProviderEntry,
    store: CredentialStore,
    env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
    force_refresh: bool,
    rejected_refresh_generation: Option<u64>,
) -> Result<CommandCredential> {
    let entry = entry.clone();
    resolve_authorized_with_executor(
        provider_id,
        store,
        env_lookup,
        force_refresh,
        rejected_refresh_generation,
        Arc::new(SubprocessCommandExecutor),
        move || Ok(entry),
    )
    .await
    .map(|(_, credential)| credential)
}

/// Resolve a command credential from the provider entry authorized at its
/// execution turn.  Long-lived clients use this for rejection-triggered
/// refreshes: config can reload while they wait for another refresh, so a
/// construction-time entry must never determine the executable that runs.
pub(crate) async fn resolve_authorized<F>(
    provider_id: &str,
    store: CredentialStore,
    env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
    force_refresh: bool,
    rejected_refresh_generation: Option<u64>,
    authorize_entry: F,
) -> Result<(
    cockpit_config::config::providers::ProviderEntry,
    CommandCredential,
)>
where
    F: FnOnce() -> Result<cockpit_config::config::providers::ProviderEntry>,
{
    resolve_authorized_with_executor(
        provider_id,
        store,
        env_lookup,
        force_refresh,
        rejected_refresh_generation,
        Arc::new(SubprocessCommandExecutor),
        authorize_entry,
    )
    .await
}

#[cfg(test)]
async fn resolve_with_executor(
    provider_id: &str,
    command: &[String],
    provider_url: &str,
    store: CredentialStore,
    env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
    force_refresh: bool,
    rejected_refresh_generation: Option<u64>,
    executor: Arc<dyn CommandSecretExecutor>,
) -> Result<CommandCredential> {
    let command = command.to_vec();
    let entry = cockpit_config::config::providers::ProviderEntry {
        url: provider_url.to_string(),
        auth_command: Some(command),
        ..cockpit_config::config::providers::ProviderEntry::default()
    };
    resolve_authorized_with_executor(
        provider_id,
        store,
        env_lookup,
        force_refresh,
        rejected_refresh_generation,
        executor,
        move || Ok(entry),
    )
    .await
    .map(|(_, credential)| credential)
}

async fn resolve_authorized_with_executor<F>(
    provider_id: &str,
    store: CredentialStore,
    env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
    force_refresh: bool,
    rejected_refresh_generation: Option<u64>,
    executor: Arc<dyn CommandSecretExecutor>,
    authorize_entry: F,
) -> Result<(
    cockpit_config::config::providers::ProviderEntry,
    CommandCredential,
)>
where
    F: FnOnce() -> Result<cockpit_config::config::providers::ProviderEntry>,
{
    let key = provider_id.to_string();
    let refresh_key = key.clone();
    crate::auth::refresh_guard::serialized_refresh(&key, move || async move {
        // This is deliberately inside `serialized_refresh`: a queued refresh
        // must re-read authorization only after it owns the execution turn.
        // There is no await between the check and `executor.run` below.
        let entry = authorize_entry()?;
        let command = entry
            .auth_command
            .as_deref()
            .context("provider has no auth_command")?;
        let provider_configuration = serde_json::to_vec(&entry)
            .context("serializing provider auth-command configuration")?;
        let argv = resolve_argv(command, &store, env_lookup)?;
        let configuration_identity = configuration_identity(&argv, &provider_configuration);
        let current = store.reopen()?;
        if let Some(cached) = load_cached(&current, &refresh_key, &configuration_identity)? {
            // A rejection is tied to the credential generation that actually
            // left the process. A late 401 for generation N must reuse the
            // winner's N+1 credential, even if it enters this lock after the
            // winner has already completed.
            let another_waiter_refreshed = force_refresh
                && rejected_refresh_generation
                    .is_some_and(|rejected| rejected != cached.refresh_generation);
            if another_waiter_refreshed
                || (!force_refresh && !cached.credential.is_expired(unix_now()))
            {
                return Ok((
                    entry,
                    CommandCredential {
                        refresh_generation: cached.refresh_generation,
                        ..cached.credential
                    },
                ));
            }
        }

        let stdout = executor
            .run(&argv)
            .await
            .map_err(|error| anyhow::anyhow!("auth command failed: {}", error.code()))?;
        let mut credential: CommandCredential =
            serde_json::from_str(&stdout).context("auth command returned malformed JSON")?;
        credential.validate()?;
        let refresh_generation = load_cached(&current, &refresh_key, &configuration_identity)?
            .map_or(1, |cached| cached.refresh_generation.saturating_add(1));
        credential.refresh_generation = refresh_generation;
        let cached = CachedCommandCredential {
            configuration_identity,
            refresh_generation,
            credential: credential.clone(),
        };
        current.save_record_merged(&refresh_key, serde_json::json!({ "auth_command": cached }))?;
        Ok((entry, credential))
    })
    .await
}

fn load_cached(
    store: &CredentialStore,
    provider_id: &str,
    configuration_identity: &str,
) -> Result<Option<CachedCommandCredential>> {
    store
        .get(provider_id)
        .and_then(|record| record.get("auth_command"))
        .cloned()
        .map(serde_json::from_value::<CachedCommandCredential>)
        .transpose()
        .context("cached auth-command credential is malformed")
        .map(|cached| {
            cached.filter(|cached| cached.configuration_identity == configuration_identity)
        })
}

fn configuration_identity(argv: &[String], provider_configuration: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((provider_configuration.len() as u64).to_be_bytes());
    hasher.update(provider_configuration);
    for part in argv {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn resolve_argv(
    command: &[String],
    store: &CredentialStore,
    env_lookup: &(dyn Fn(&str) -> Option<String> + Sync),
) -> Result<Vec<String>> {
    anyhow::ensure!(!command.is_empty(), "auth_command is empty");
    let mut argv = Vec::with_capacity(command.len());
    let mut missing = Vec::new();
    let mut errors = Vec::new();
    for item in command {
        let resolved = crate::envref::resolve_with_sources(item, env_lookup, |name| {
            store.named_secret(name).map(str::to_string)
        });
        missing.extend(resolved.missing);
        errors.extend(resolved.errors);
        argv.push(resolved.value);
    }
    anyhow::ensure!(
        errors.is_empty(),
        "auth_command contains invalid references"
    );
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

    fn cached(token: &str, expires_at: Option<i64>) -> serde_json::Value {
        let entry = cockpit_config::config::providers::ProviderEntry {
            url: "https://example.test/v1".into(),
            auth_command: Some(vec!["auth-helper".into()]),
            ..cockpit_config::config::providers::ProviderEntry::default()
        };
        serde_json::json!({
            "configuration_identity": configuration_identity(
                &["auth-helper".to_string()],
                &serde_json::to_vec(&entry).unwrap(),
            ),
            "refresh_generation": 1,
            "credential": { "token": token, "expires_at": expires_at, "headers": null }
        })
    }

    #[tokio::test]
    async fn valid_json_is_cached_under_provider_record() {
        let (_temp, store) = store();
        let executor = FakeExecutor::new([Ok(
            r#"{"token":"fresh-token","expires_at":null,"headers":{"X-Tenant":"one"}}"#.into(),
        )]);
        let credential = resolve_with_executor(
            "custom",
            &["auth-helper".into()],
            "https://example.test/v1",
            store.clone(),
            &|_| None,
            false,
            None,
            executor.clone(),
        )
        .await
        .unwrap();

        assert_eq!(credential.token, "fresh-token");
        assert_eq!(
            store.reopen().unwrap().get("custom").unwrap()["auth_command"]["credential"]["token"],
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
            "https://example.test/v1",
            store.clone(),
            &|_| None,
            false,
            None,
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
            "https://example.test/v1",
            store,
            &|_| None,
            false,
            None,
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
                "auth_command": cached("expired", Some(1))
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
                    "https://example.test/v1",
                    store,
                    &|_| None,
                    false,
                    None,
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
    async fn late_rejection_for_prior_generation_reuses_the_winning_refresh() {
        let (_temp, mut store) = store();
        store.set(
            "custom-401",
            serde_json::json!({
                "auth_command": cached("rejected", None)
            }),
        );
        store.save().unwrap();
        let executor = FakeExecutor::new([Ok(
            r#"{"token":"rejected","expires_at":null,"headers":null}"#.into(),
        )]);

        let run = || {
            let executor = executor.clone();
            let store = store.clone();
            async move {
                resolve_with_executor(
                    "custom-401",
                    &["auth-helper".into()],
                    "https://example.test/v1",
                    store,
                    &|_| None,
                    true,
                    Some(1),
                    executor,
                )
                .await
            }
        };
        // Simulate request A refreshing while request B (sent with generation
        // 1) is still in flight. B only observes its 401 after A has finished;
        // its rejected-generation identity must still suppress another exec.
        let first = run().await;
        let second = run().await;

        assert_eq!(first.unwrap().token, "rejected");
        assert_eq!(second.unwrap().token, "rejected");
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cache_is_not_reused_after_command_destination_changes() {
        let (_temp, store) = store();
        let executor = FakeExecutor::new([
            Ok(r#"{"token":"first","expires_at":null,"headers":null}"#.into()),
            Ok(r#"{"token":"second","expires_at":null,"headers":null}"#.into()),
        ]);

        resolve_with_executor(
            "custom",
            &["auth-helper".into()],
            "https://first.example/v1",
            store.clone(),
            &|_| None,
            false,
            None,
            executor.clone(),
        )
        .await
        .unwrap();
        let credential = resolve_with_executor(
            "custom",
            &["auth-helper".into()],
            "https://second.example/v1",
            store,
            &|_| None,
            false,
            None,
            executor.clone(),
        )
        .await
        .unwrap();

        assert_eq!(credential.token, "second");
        assert_eq!(executor.calls.load(Ordering::SeqCst), 2);
    }
}
