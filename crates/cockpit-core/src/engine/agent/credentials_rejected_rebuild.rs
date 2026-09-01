//! Credentials-rejected rebuild-and-retry for command-based authentication.
//!
//! Resolution point #3 from `command-backed-secret-refs-daemon`: when a
//! provider request fails with an auth error classified
//! [`AuthFailureKind::CredentialsRejected`](crate::daemon::proto::AuthFailureKind::CredentialsRejected)
//! (HTTP 401/403), a short-lived command-backed token (`gh auth token`, `op`,
//! `pass`, …) may simply have gone stale in the daemon cache. Rather than
//! surfacing the failure immediately, the turn-dispatch seam does ONE
//! re-resolve + **rebuild of the model client** + one retry, latched:
//!
//! 1. Refresh the failing provider's global `auth_command`, or invalidate and
//!    re-resolve its owner-scoped command-backed named secret(s).
//! 2. Rebuild a FRESH model client through the
//!    [`Model::for_provider_with_store`](crate::engine::model::Model::for_provider_with_store)
//!    template so the new client picks up the freshly-resolved secret. This is a
//!    NEW model instance — the stale one is discarded.
//! 3. Retry the turn ONCE against the rebuilt model.
//!
//! A `credentials_rebuild_used` latch (mirroring the `overload_retry_used` /
//! `billing_backup_used` latches in the same dispatch loop) blocks a SECOND
//! automatic rebuild-and-retry: a second consecutive `CredentialsRejected`
//! surfaces the auth error to the user with no further re-resolve/exec/retry.
//! The latch is scoped to a single dispatch, so a later INDEPENDENT rejection
//! (a fresh turn, after an intervening success) can rebuild-and-retry again.

use std::sync::Arc;

use std::collections::HashMap;
use std::sync::RwLock;

use crate::engine::model::Model;
use crate::redact::RedactionTable;
use crate::session::Session;

/// The agent env overlay threaded into a rebuilt model's `$env:` lookup.
type EnvOverlay = Arc<RwLock<HashMap<String, String>>>;

/// Whether `err` is a terminal inference failure whose auth classification is
/// [`AuthFailureKind::CredentialsRejected`](crate::daemon::proto::AuthFailureKind::CredentialsRejected)
/// (HTTP 401/403). Every other class — OAuth-expired, missing-entitlement,
/// provider-not-configured, a rate limit (429), a 5xx, a timeout — returns
/// `false` and is never rebuilt-and-retried here.
pub(crate) fn is_credentials_rejected(err: &anyhow::Error) -> bool {
    crate::engine::model::as_inference_failure(err)
        .and_then(crate::engine::model::auth_failure_kind)
        .is_some_and(|kind| {
            matches!(
                kind,
                crate::daemon::proto::AuthFailureKind::CredentialsRejected { .. }
            )
        })
}

/// [`is_credentials_rejected`] lifted over a turn `Result`: `true` only when the
/// result is an `Err` carrying a `CredentialsRejected` inference failure. Returns
/// a plain `bool` so the caller holds no borrow of the result across the
/// rebuild-and-retry decision.
pub(crate) fn result_is_credentials_rejected<T>(result: &anyhow::Result<T>) -> bool {
    result.as_ref().err().is_some_and(is_credentials_rejected)
}

/// The latch predicate: attempt the (single) rebuild-and-retry only when the
/// current attempt was rejected for credentials AND no rebuild has yet been used
/// on this dispatch. Extracted so the production dispatch loop and the AC5 tests
/// share ONE definition of the latch decision — removing the `!already_used`
/// term (a "no-latch" regression) would let a second consecutive rejection loop.
pub(crate) fn should_attempt_credentials_rebuild(is_rejected: bool, already_used: bool) -> bool {
    is_rejected && !already_used
}

/// A freshly-rebuilt model client paired with the refreshed redaction table it
/// must be dispatched under. The table is the current table unioned with a table
/// built from the refreshed owner-scoped store, so the freshly-resolved token is
/// scrubbed on every channel of the retry (request recording, diagnostics,
/// provider echo). In-memory only — the command output is never persisted.
pub(crate) struct RebuiltCredentialsModel {
    pub model: Model,
    pub redact: Arc<RedactionTable>,
}

/// Re-resolve the command-backed secret(s) for `current_model`'s FAILING
/// provider and rebuild a FRESH [`Model`] client that picks up the re-resolved
/// value, under a REFRESHED redaction table.
///
/// - `Ok(None)` — the failing provider has NO owner-scoped command-backed secret
///   (only a static/env/literal credential): no exec, no rebuild, no retry. The
///   caller surfaces the original auth error immediately.
/// - `Ok(Some(..))` — a command-backed secret was re-resolved and a fresh client
///   built under a refreshed redaction table.
/// - `Err(..)` — the rebuild itself failed (unconfigured provider / bad id /
///   store failure); the caller surfaces the ORIGINAL auth failure.
///
/// Step (a) invalidates + re-resolves ONLY the failing provider's command
/// secret(s) through the session owner-scoped view
/// ([`Session::reresolve_provider_command_secrets`]) and reports eligibility.
/// Step (b) builds a refreshed redaction table from the refreshed owner-scoped
/// store and unions it with the current table. Step (c) rebuilds via the
/// [`Model::for_provider_with_store`] template (mirroring the driver's
/// `build_live_model_for_running_with_active`), threading the refreshed table,
/// the owner-scoped store, and the agent's env overlay. The rebuilt model is a
/// NEW instance and does NOT inherit the stale model's live wire-API self-heal
/// state, so the retry dials with the freshly-resolved credential.
pub(crate) async fn rebuild_model_for_credentials(
    session: &Session,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    redact: &Arc<RedactionTable>,
    env_overlay: &EnvOverlay,
    current_model: &Model,
) -> anyhow::Result<Option<RebuiltCredentialsModel>> {
    let (extended, providers) = config.configs();
    let provider_id = current_model.provider_id();
    // (a) Eligibility + provider-scoped re-resolution: invalidate + re-resolve
    // ONLY the failing provider's owner-scoped command secret(s). Returns false
    // (⇒ no rebuild/retry) when this provider is not command-backed.
    let reresolved = if session
        .refresh_provider_auth_command(&providers, provider_id)
        .await?
    {
        true
    } else {
        session
            .reresolve_provider_command_secrets(&providers, provider_id)
            .await
    };
    if !reresolved {
        return Ok(None);
    }
    // The owner-scoped store now carries the freshly-resolved output.
    let store = session.provider_credential_store(&providers)?;
    // (b) Refreshed redaction table: union the current table with one built from
    // the refreshed store (which injects the fresh command output), so the NEW
    // token is scrubbed everywhere on the retry. In-memory only.
    let env = env_overlay
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let refreshed_secrets = RedactionTable::build_with_env_and_credential_store(
        &extended.redact,
        &session.project_root,
        &env,
        &store,
    )?;
    let refreshed_secrets = session
        .with_machine_scoped_sealed_redactions(&refreshed_secrets)
        .await?;
    let refreshed = Arc::new(redact.union(&refreshed_secrets)?);
    // (c) Rebuild a fresh client from the owner-scoped store under the refreshed
    // table. Same construction funnel as the model-swap path.
    let env_overlay = env_overlay.clone();
    let built = Model::for_provider_with_store(
        &providers,
        provider_id,
        current_model.model_id_ref(),
        refreshed.clone(),
        move |name| {
            env_overlay
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(name)
                .cloned()
        },
        store,
    )?
    .with_shutdown_gate(current_model.shutdown_gate());
    Ok(Some(RebuiltCredentialsModel {
        model: built,
        redact: refreshed,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::engine::model::{InferenceErrorClass, InferenceFailure};
    use crate::secret_command::{CommandSecretCache, CommandSecretError, CommandSecretExecutor};

    fn failure(class: InferenceErrorClass) -> anyhow::Error {
        anyhow::Error::new(InferenceFailure {
            provider: "mock-provider".into(),
            model: "mock-model".into(),
            phase: "dispatched".into(),
            class,
            elapsed_ms: 1,
            retry_attempts: 1,
            detail: "boom".into(),
            observed_status: None,
            recovery: crate::engine::model::ProviderRecoverySignal::None,
        })
    }

    #[test]
    fn classifier_matches_only_401_and_403() {
        assert!(is_credentials_rejected(&failure(
            InferenceErrorClass::Http(401)
        )));
        assert!(is_credentials_rejected(&failure(
            InferenceErrorClass::Http(403)
        )));
        // A rate limit and a 5xx are NOT credentials rejections.
        assert!(!is_credentials_rejected(&failure(
            InferenceErrorClass::Http(429)
        )));
        assert!(!is_credentials_rejected(&failure(
            InferenceErrorClass::Http(500)
        )));
        // An arbitrary non-inference error is not a credentials rejection.
        assert!(!is_credentials_rejected(&anyhow::anyhow!("unrelated")));
    }

    #[test]
    fn result_classifier_only_fires_on_credentials_err() {
        let ok: anyhow::Result<u8> = Ok(1);
        assert!(!result_is_credentials_rejected(&ok));
        let rejected: anyhow::Result<u8> = Err(failure(InferenceErrorClass::Http(401)));
        assert!(result_is_credentials_rejected(&rejected));
        let other: anyhow::Result<u8> = Err(failure(InferenceErrorClass::Http(500)));
        assert!(!result_is_credentials_rejected(&other));
    }

    #[test]
    fn latch_predicate_is_one_shot() {
        assert!(should_attempt_credentials_rebuild(true, false));
        // Latched: a second rejection on the same dispatch is not retried.
        assert!(!should_attempt_credentials_rebuild(true, true));
        // A non-credentials failure is never rebuilt-and-retried.
        assert!(!should_attempt_credentials_rebuild(false, false));
    }

    // ------------------------------------------------------------------
    // Real-path fixtures: a session whose vault holds command-backed secrets,
    // owner-scoped to (provider, project_root), plus a counting/recording/
    // sequencing executor cache. These drive the REAL production functions
    // (`Session::reresolve_provider_command_secrets`,
    // `rebuild_model_for_credentials`) — not a replica.
    // ------------------------------------------------------------------

    use std::sync::Mutex;

    use crate::config::extended::ExtendedConfig;
    use crate::config::providers::{HeaderSpec, ModelEntry, ProviderEntry, ProvidersConfig};
    use crate::daemon::session_worker::{SessionConfigHandle, SessionConfigSnapshot};

    /// Returns canned values by invocation order (e.g. `["stale", "fresh"]`), so
    /// a rebuild observes a DIFFERENT resolved token than startup did.
    struct SequencedExecutor {
        values: Vec<String>,
        next: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl CommandSecretExecutor for SequencedExecutor {
        async fn run(&self, _argv: &[String]) -> Result<String, CommandSecretError> {
            let index = self.next.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .values
                .get(index)
                .cloned()
                .unwrap_or_else(|| "unexpected-extra-call".to_string()))
        }
    }

    /// Always fails to resolve (a broken command spec).
    struct FailingExecutor;

    #[async_trait::async_trait]
    impl CommandSecretExecutor for FailingExecutor {
        async fn run(&self, _argv: &[String]) -> Result<String, CommandSecretError> {
            Err(CommandSecretError::NotFound)
        }
    }

    /// Records the `argv[0]` of every command it runs, so a test can prove which
    /// provider's secret was (not) executed.
    struct RecordingExecutor {
        ran: Mutex<Vec<String>>,
        token: String,
    }

    #[async_trait::async_trait]
    impl CommandSecretExecutor for RecordingExecutor {
        async fn run(&self, argv: &[String]) -> Result<String, CommandSecretError> {
            self.ran
                .lock()
                .unwrap()
                .push(argv.first().cloned().unwrap_or_default());
            Ok(self.token.clone())
        }
    }

    /// Claim `(provider, project_root)` ownership of a named secret so the owner-
    /// scoped resolution/injection view resolves it (mirrors the ownership row a
    /// provider save inserts).
    fn claim_provider_ownership(db: &crate::db::Db, item_id: &str, project_root: &std::path::Path) {
        let root =
            crate::secret_ownership::canonical_owner_root(&project_root.display().to_string());
        let item_id = item_id.to_string();
        db.blocking_write_for_sync_maintenance(move |conn| {
            conn.execute(
                "INSERT INTO secret_named_ownership (item_id, owner_kind, project_root, created_at)
                 VALUES (?1, 'provider', ?2, 0)",
                rusqlite::params![item_id, root],
            )?;
            Ok(())
        })
        .unwrap();
    }

    /// A session whose vault holds the given command-backed secrets, each claimed
    /// as provider-owned so the owner-scoped store resolves it.
    fn session_with_command_secrets(command_specs: &[(&str, Vec<String>)]) -> Arc<Session> {
        let db = crate::db::Db::open_in_memory().unwrap();
        let root = tempfile::tempdir().unwrap().keep();
        let session = Arc::new(
            crate::session::Session::create_for_test(
                db.clone(),
                root,
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let mut store = crate::credentials::CredentialStore::from_vault(vault).unwrap();
        for (name, argv) in command_specs {
            store.set_named_secret_command(*name, argv.clone()).unwrap();
        }
        store.save().unwrap();
        for (name, _) in command_specs {
            claim_provider_ownership(&db, name, &session.project_root);
        }
        session
    }

    fn provider_referencing(model: &str, url: &str, secret: &str) -> ProviderEntry {
        ProviderEntry {
            url: url.to_string(),
            models: vec![ModelEntry {
                id: model.to_string(),
                ..ModelEntry::default()
            }],
            headers: vec![HeaderSpec {
                name: "Authorization".to_string(),
                value: format!("Bearer $secret:{secret}"),
            }],
            ..ProviderEntry::default()
        }
    }

    fn empty_env() -> EnvOverlay {
        Arc::new(RwLock::new(HashMap::new()))
    }

    /// HIGH #1 + #2: re-resolution is scoped to the FAILING provider and reports
    /// eligibility. A 401 on provider `alpha` re-resolves ONLY `alpha`'s command
    /// secret (never sibling `beta`'s), and a provider with no command-backed
    /// secret reports `false` (⇒ no rebuild, no retry) and never execs.
    #[tokio::test]
    async fn reresolve_is_scoped_to_failing_provider_and_reports_eligibility() {
        let session = session_with_command_secrets(&[
            (
                "alpha-cmd",
                vec!["alpha-prog".to_string(), "token".to_string()],
            ),
            (
                "beta-cmd",
                vec!["beta-prog".to_string(), "token".to_string()],
            ),
        ]);
        let recorder = Arc::new(RecordingExecutor {
            ran: Mutex::new(Vec::new()),
            token: "tok".to_string(),
        });
        let cache = CommandSecretCache::new(recorder.clone());
        session.set_command_secret_cache(Some(cache.clone()));

        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            "alpha".to_string(),
            provider_referencing("m", "http://localhost:9/v1", "alpha-cmd"),
        );
        providers.providers.insert(
            "beta".to_string(),
            provider_referencing("m", "http://localhost:9/v1", "beta-cmd"),
        );
        // A provider with no `$secret:` header at all: not eligible.
        providers.providers.insert(
            "gamma".to_string(),
            ProviderEntry {
                url: "http://localhost:9/v1".to_string(),
                models: vec![ModelEntry {
                    id: "m".to_string(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        // Failing provider = alpha: re-resolves alpha's secret only.
        assert!(
            session
                .reresolve_provider_command_secrets(&providers, "alpha")
                .await,
            "alpha is command-backed ⇒ eligible"
        );
        assert_eq!(
            *recorder.ran.lock().unwrap(),
            vec!["alpha-prog".to_string()],
            "a 401 on alpha must re-resolve ONLY alpha's command secret, never beta's"
        );

        // A provider with no command-backed secret is not eligible and never execs.
        assert!(
            !session
                .reresolve_provider_command_secrets(&providers, "gamma")
                .await,
            "gamma has no command-backed secret ⇒ not eligible"
        );
        assert_eq!(
            recorder.ran.lock().unwrap().len(),
            1,
            "an ineligible provider must not exec any command"
        );
    }

    /// MEDIUM: a referenced command secret that FAILS to resolve is NOT eligible.
    /// Eligibility counts only `Resolved` re-resolutions, so a broken command
    /// (still-401 credential) surfaces the original error instead of firing a
    /// wasted rebuild-and-retry that 401s again.
    #[tokio::test]
    async fn failed_command_reresolution_is_not_eligible() {
        let session =
            session_with_command_secrets(&[("bad-cmd", vec!["missing-prog".to_string()])]);
        let cache = CommandSecretCache::new(Arc::new(FailingExecutor));
        session.set_command_secret_cache(Some(cache.clone()));

        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            "cloud".to_string(),
            provider_referencing("m", "http://localhost:9/v1", "bad-cmd"),
        );

        assert!(
            !session
                .reresolve_provider_command_secrets(&providers, "cloud")
                .await,
            "a command that fails to resolve must NOT be eligible for rebuild-and-retry"
        );
        // It DID attempt the command (exactly once) — it simply failed.
        assert_eq!(cache.exec_count(), 1);
        assert!(matches!(
            cache.status("bad-cmd"),
            Some(crate::secret_command::CommandResolutionStatus::Failed(_))
        ));
    }

    /// HIGH #2: a provider with no command-backed secret is never rebuilt-and-
    /// retried — `rebuild_model_for_credentials` returns `Ok(None)` with zero exec.
    #[tokio::test]
    async fn rebuild_is_skipped_for_a_provider_without_a_command_secret() {
        // A session with a command secret that belongs to a DIFFERENT provider,
        // proving the gate is per-failing-provider, not "any command secret".
        let session =
            session_with_command_secrets(&[("other-cmd", vec!["other-prog".to_string()])]);
        let cache = CommandSecretCache::new(Arc::new(SequencedExecutor {
            values: vec!["tok".to_string()],
            next: AtomicUsize::new(0),
        }));
        session.set_command_secret_cache(Some(cache.clone()));

        let mut providers = ProvidersConfig::default();
        // The failing provider has only a static Authorization header.
        providers.providers.insert(
            "static".to_string(),
            ProviderEntry {
                url: "http://localhost:9/v1".to_string(),
                models: vec![ModelEntry {
                    id: "m".to_string(),
                    ..ModelEntry::default()
                }],
                headers: vec![HeaderSpec {
                    name: "Authorization".to_string(),
                    value: "Bearer static-literal-key".to_string(),
                }],
                ..ProviderEntry::default()
            },
        );
        let handle = SessionConfigHandle::detached(SessionConfigSnapshot::new(
            0,
            providers.clone(),
            ExtendedConfig::default(),
        ));
        let base = Arc::new(RedactionTable::empty());
        let current_model = Model::for_provider(&providers, "static", "m", base.clone()).unwrap();

        let rebuilt =
            rebuild_model_for_credentials(&session, &handle, &base, &empty_env(), &current_model)
                .await
                .unwrap();
        assert!(
            rebuilt.is_none(),
            "a provider with no command-backed secret must not rebuild-and-retry"
        );
        assert_eq!(
            cache.exec_count(),
            0,
            "an ineligible provider must never exec"
        );
    }

    /// HIGH #4: the rebuilt model is dispatched under a REFRESHED redaction table
    /// that scrubs the freshly-resolved token (no leak). Also proves the rebuild
    /// re-resolves exactly once and yields a fresh client for the failing provider.
    #[tokio::test]
    async fn rebuild_refreshes_token_into_redaction_table() {
        let session = session_with_command_secrets(&[(
            "gh-cmd",
            vec![
                "gh-prog".to_string(),
                "auth".to_string(),
                "token".to_string(),
            ],
        )]);
        // startup resolves "stale-token"; the rebuild re-resolves "fresh-token".
        let cache = CommandSecretCache::new(Arc::new(SequencedExecutor {
            values: vec![
                "stale-token-aaaaaaaaaaaa".to_string(),
                "fresh-token-bbbbbbbbbbbb".to_string(),
            ],
            next: AtomicUsize::new(0),
        }));
        session.set_command_secret_cache(Some(cache.clone()));

        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            "cloud".to_string(),
            provider_referencing("m", "http://localhost:9/v1", "gh-cmd"),
        );
        let handle = SessionConfigHandle::detached(SessionConfigSnapshot::new(
            0,
            providers.clone(),
            ExtendedConfig::default(),
        ));

        // Startup resolution puts "stale-token" in the cache (exec 1).
        assert!(
            session
                .reresolve_provider_command_secrets(&providers, "cloud")
                .await
        );
        assert_eq!(cache.exec_count(), 1);

        // The CURRENT session table does not yet scrub the fresh token.
        let base = Arc::new(RedactionTable::empty());
        assert_eq!(
            base.scrub("fresh-token-bbbbbbbbbbbb"),
            "fresh-token-bbbbbbbbbbbb",
            "precondition: the fresh token is not yet redacted"
        );

        // Built with the owner-scoped store so the `$secret:` header resolves
        // (from the cached "stale" value) at construction time.
        let store = session.provider_credential_store(&providers).unwrap();
        let current_model = Model::for_provider_with_store(
            &providers,
            "cloud",
            "m",
            base.clone(),
            |_name: &str| -> Option<String> { None },
            store,
        )
        .unwrap();
        let rebuilt =
            rebuild_model_for_credentials(&session, &handle, &base, &empty_env(), &current_model)
                .await
                .unwrap()
                .expect("cloud is command-backed ⇒ a rebuilt client");

        assert_eq!(
            cache.exec_count(),
            2,
            "the rebuild re-resolves exactly once"
        );
        assert_eq!(rebuilt.model.provider_id(), "cloud");
        // HIGH #4: the freshly-resolved token IS scrubbed by the refreshed table
        // the rebuilt model is dispatched under — a stale-table rebuild would let
        // the new token evade redaction.
        assert_ne!(
            rebuilt.redact.scrub("fresh-token-bbbbbbbbbbbb"),
            "fresh-token-bbbbbbbbbbbb",
            "the refreshed redaction table must scrub the freshly-resolved token"
        );
    }
}
