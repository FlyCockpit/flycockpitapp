//! Daemon-owned recovery for the effective-default journal.
//!
//! `cockpit-config` owns the journal state machine but has no session
//! authority and no event bus. This module supplies both, so startup and
//! attach can converge a session+default transaction — not just its config
//! half — before any session or default snapshot is served, and can emit the
//! one correlated terminal event the originating client is still waiting for.

use std::path::Path;

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::config::providers::{ActiveModelRef, RecoveredTransaction, SessionRevisionAuthority};
use crate::db::Db;

/// SQLite-backed [`SessionRevisionAuthority`].
///
/// Every mutation is a guarded compare-and-swap on `active_model_revision`, so
/// a session that moved on since the journal was written is reported as a
/// conflict instead of being overwritten by compensation. Unbound: it may act
/// on any session row, and proves the row exists rather than assuming it.
pub struct DbSessionRevisionAuthority<'a> {
    db: &'a Db,
}

impl<'a> DbSessionRevisionAuthority<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }
}

impl SessionRevisionAuthority for DbSessionRevisionAuthority<'_> {
    fn current_revision(&mut self, session_id: Uuid) -> Result<Option<i64>> {
        self.db
            .blocking_read_for_sync_ui(move |conn| Db::active_model_revision_conn(conn, session_id))
            .context("reading session active_model_revision for journal recovery")
    }

    fn cas_set_active_model(
        &mut self,
        session_id: Uuid,
        expected_revision: i64,
        selection: &ActiveModelRef,
    ) -> Result<bool> {
        let selection_json =
            serde_json::to_string(selection).context("encoding recovered session model")?;
        let provider = selection.provider.clone();
        let model = selection.model.clone();
        self.db
            .blocking_write_for_sync_maintenance(move |conn| {
                Db::cas_set_active_model_conn(
                    conn,
                    session_id,
                    expected_revision,
                    &provider,
                    &model,
                    &selection_json,
                )
            })
            .context("restoring session active model during journal recovery")
    }
}

/// Blocking, idempotent recovery of every effective-default journal that
/// applies to `cwd`, with full session authority.
///
/// Converged transactions are handed to `collected` **before** their journal
/// is deleted, so a terminal result can never be dropped by cleanup.
pub fn recover_effective_default_journals_blocking(
    db: &Db,
    cwd: &Path,
    collected: &mut Vec<RecoveredTransaction>,
) -> Result<()> {
    let mut authority = DbSessionRevisionAuthority::new(db);
    let mut sink = |transaction: &RecoveredTransaction| -> Result<()> {
        collected.push(transaction.clone());
        Ok(())
    };
    let recovery = crate::config::providers::JournalRecovery::with_sessions(&mut authority)
        .with_sink(&mut sink);
    crate::config::providers::recover_all_effective_default_journals(cwd, recovery)?;
    Ok(())
}

/// Run recovery off the async runtime under `trust_policy`, so project layers
/// are discovered exactly as attach would read them.
///
/// The converged transactions are returned rather than emitted here: emission
/// must go through the session's driver, which owns the generation a client's
/// terminal gate compares against. Callers pass the result to
/// [`deliver_recovered_terminals`] once a worker handle exists.
pub async fn recover_effective_default_journals(
    db: &Db,
    cwd: &Path,
    trust_policy: Option<crate::config::trust::WorkspaceTrustPolicy>,
) -> Result<Vec<RecoveredTransaction>> {
    let db = db.clone();
    let cwd = cwd.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut collected = Vec::new();
        let result = match trust_policy {
            Some(policy) => crate::config::trust::with_workspace_trust_policy(policy, || {
                recover_effective_default_journals_blocking(&db, &cwd, &mut collected)
            }),
            None => recover_effective_default_journals_blocking(&db, &cwd, &mut collected),
        };
        result.map(|()| collected)
    })
    .await
    .context("joining effective-default journal recovery")?
}

/// Hand converged transactions to the sessions that own them.
///
/// Routed through `SessionWork` so the driver stamps its own
/// active-model-state generation onto the terminal event. A session with no
/// live worker has no client waiting on this daemon, so the converged durable
/// state — which the next attach serves — is the whole result; the undelivered
/// correlation is logged rather than silently discarded.
pub async fn deliver_recovered_terminals(
    ctx: &crate::daemon::server::DaemonContext,
    recovered: Vec<RecoveredTransaction>,
) {
    if recovered.is_empty() {
        return;
    }
    let mut by_session: std::collections::HashMap<Uuid, Vec<RecoveredTransaction>> =
        std::collections::HashMap::new();
    for transaction in recovered {
        by_session
            .entry(transaction.correlation.session_id())
            .or_default()
            .push(transaction);
    }
    for (session_id, transactions) in by_session {
        let Some(handle) = ctx.registry.live_handle(session_id) else {
            tracing::info!(
                %session_id,
                count = transactions.len(),
                "converged effective-default transactions for a session with no live worker; \
                 the next attach serves the converged snapshot"
            );
            continue;
        };
        if let Err(error) = handle
            .send_work(
                crate::daemon::session_worker::SessionWork::EmitRecoveredDefaultTerminals {
                    transactions,
                },
            )
            .await
        {
            tracing::warn!(%error, %session_id, "could not deliver recovered terminal results");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{
        ActiveModelWriteMode, SessionDefaultParticipant, TransactionCorrelation,
        mutate_effective_default,
    };

    fn selection(provider: &str, model: &str) -> ActiveModelRef {
        ActiveModelRef {
            provider: provider.to_string(),
            model: model.to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        }
    }

    fn write_layer(dir: &Path, active: Option<&ActiveModelRef>) {
        std::fs::create_dir_all(dir).unwrap();
        let mut raw = serde_json::json!({});
        if let Some(active) = active {
            raw["active_model"] = serde_json::to_value(active).unwrap();
        }
        std::fs::write(
            dir.join("config.json"),
            format!("{}\n", serde_json::to_string_pretty(&raw).unwrap()),
        )
        .unwrap();
        let providers = dir.join("providers");
        std::fs::create_dir_all(&providers).unwrap();
        std::fs::write(
            providers.join("new.json"),
            r#"{"url":"https://example.test/v1","models":[{"id":"b"}]}"#,
        )
        .unwrap();
    }

    /// The SQLite authority must guard on the durable revision, not merely
    /// write: a stale expectation is a conflict, never an overwrite.
    #[tokio::test]
    async fn db_session_authority_reads_and_guards_the_durable_revision() {
        let db = Db::open_in_memory().unwrap();
        let row = db
            .create_session("p", "/tmp/p", "orchestrator-build")
            .await
            .unwrap();
        let session_id = row.session_id;

        let db_for_blocking = db.clone();
        let (revision, committed, stale, after) = tokio::task::spawn_blocking(move || {
            let mut authority = DbSessionRevisionAuthority::new(&db_for_blocking);
            let revision = authority.current_revision(session_id).unwrap();
            let committed = authority
                .cas_set_active_model(session_id, 0, &selection("p", "m"))
                .unwrap();
            let stale = authority
                .cas_set_active_model(session_id, 0, &selection("other", "x"))
                .unwrap();
            let after = authority.current_revision(session_id).unwrap();
            (revision, committed, stale, after)
        })
        .await
        .unwrap();

        assert_eq!(revision, Some(0));
        assert!(committed);
        assert!(!stale, "a stale guard revision must be a conflict");
        assert_eq!(after, Some(1));

        let loaded = db.get_session(session_id).await.unwrap().unwrap();
        assert_eq!(loaded.provider.as_deref(), Some("p"));
        assert_eq!(loaded.active_model_revision, 1);
    }

    #[tokio::test]
    async fn db_session_authority_reports_a_missing_session_row() {
        let db = Db::open_in_memory().unwrap();
        let missing = Uuid::new_v4();
        let db_for_blocking = db.clone();
        let revision = tokio::task::spawn_blocking(move || {
            DbSessionRevisionAuthority::new(&db_for_blocking)
                .current_revision(missing)
                .unwrap()
        })
        .await
        .unwrap();
        assert_eq!(revision, None);
    }

    /// The daemon half of the crash matrix: every phase boundary replayed
    /// through `DbSessionRevisionAuthority` against real SQLite. After
    /// recovery the config default and the durable session row must agree —
    /// never one target and one prior.
    #[tokio::test]
    async fn every_crash_phase_converges_both_authorities_through_real_sqlite() {
        use crate::config::providers::{EffectiveDefaultCrashPoint, set_crash_inject};

        const PHASES: &[EffectiveDefaultCrashPoint] = &[
            EffectiveDefaultCrashPoint::AfterJournalPrepared,
            EffectiveDefaultCrashPoint::AfterPrivateReplacementPrepared,
            EffectiveDefaultCrashPoint::AfterSessionCas,
            EffectiveDefaultCrashPoint::AfterSessionCommittedMarker,
            EffectiveDefaultCrashPoint::AfterConfigReplaced,
            EffectiveDefaultCrashPoint::AfterCommittedMarker,
            EffectiveDefaultCrashPoint::AfterReloadVerified,
            EffectiveDefaultCrashPoint::AfterJournalCleanup,
        ];

        for phase in PHASES {
            let tmp = tempfile::tempdir().unwrap();
            let _env =
                cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;
            crate::config::trust::clear_runtime_policy_for_tests();
            write_layer(
                &tmp.path().join("home/.config/cockpit"),
                Some(&selection("old", "a")),
            );
            let cwd = tmp.path().join("proj");
            std::fs::create_dir_all(&cwd).unwrap();

            let db = Db::open_in_memory().unwrap();
            let row = db
                .create_session("p", cwd.to_str().unwrap(), "orchestrator-build")
                .await
                .unwrap();
            let session_id = row.session_id;

            let db_for_blocking = db.clone();
            let cwd_for_blocking = cwd.clone();
            let phase = *phase;
            tokio::task::spawn_blocking(move || {
                let target = selection("new", "b");
                // Seed the durable session with the prior model so "converged
                // to prior" is an observable value on both sides rather than
                // the absence of one.
                {
                    let mut authority = DbSessionRevisionAuthority::new(&db_for_blocking);
                    assert!(
                        authority
                            .cas_set_active_model(session_id, 0, &selection("old", "a"))
                            .unwrap()
                    );
                }
                {
                    let mut authority = DbSessionRevisionAuthority::new(&db_for_blocking);
                    let participant = SessionDefaultParticipant {
                        session_id,
                        prior: selection("old", "a"),
                        expected_revision: 1,
                        authority: &mut authority,
                    };
                    set_crash_inject(Some(phase));
                    let _ = mutate_effective_default(
                        &cwd_for_blocking,
                        Some(&target),
                        ActiveModelWriteMode::Replace,
                        Some(participant),
                        None,
                        None,
                    );
                    set_crash_inject(None);
                }
                // Two passes: recovery must be idempotent.
                let mut collected = Vec::new();
                recover_effective_default_journals_blocking(
                    &db_for_blocking,
                    &cwd_for_blocking,
                    &mut collected,
                )
                .unwrap_or_else(|error| panic!("{phase:?}: recovery failed: {error:#}"));
                recover_effective_default_journals_blocking(
                    &db_for_blocking,
                    &cwd_for_blocking,
                    &mut collected,
                )
                .unwrap_or_else(|error| panic!("{phase:?}: second pass failed: {error:#}"));
            })
            .await
            .unwrap();

            let loaded = db.get_session(session_id).await.unwrap().unwrap();
            let config_default =
                crate::config::providers::ConfigDoc::load_effective(&cwd).active_model;
            assert_eq!(
                config_default
                    .as_ref()
                    .map(|active| active.provider.clone()),
                loaded.provider.clone(),
                "{phase:?} left the config default and the durable session model divergent"
            );
            assert!(
                matches!(
                    config_default
                        .as_ref()
                        .map(|active| active.provider.as_str()),
                    Some("old") | Some("new")
                ),
                "{phase:?} converged to neither recorded value: {config_default:?}"
            );
        }
    }

    /// A real session+default transaction against real SQLite: both durable
    /// authorities agree, the journal is gone, and a following recovery pass
    /// is a clean no-op.
    #[tokio::test]
    async fn session_and_default_transaction_converges_against_real_sqlite() {
        let tmp = tempfile::tempdir().unwrap();
        let _env =
            cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;
        crate::config::trust::clear_runtime_policy_for_tests();
        write_layer(
            &tmp.path().join("home/.config/cockpit"),
            Some(&selection("old", "a")),
        );
        let cwd = tmp.path().join("proj");
        std::fs::create_dir_all(&cwd).unwrap();

        let db = Db::open_in_memory().unwrap();
        let row = db
            .create_session("p", cwd.to_str().unwrap(), "orchestrator-build")
            .await
            .unwrap();
        let session_id = row.session_id;
        let selection_id = Uuid::new_v4();

        let db_for_blocking = db.clone();
        let cwd_for_blocking = cwd.clone();
        let (result, recovered) = tokio::task::spawn_blocking(move || {
            let target = selection("new", "b");
            let result = {
                let mut authority = DbSessionRevisionAuthority::new(&db_for_blocking);
                let participant = SessionDefaultParticipant {
                    session_id,
                    prior: selection("old", "a"),
                    expected_revision: 0,
                    authority: &mut authority,
                };
                mutate_effective_default(
                    &cwd_for_blocking,
                    Some(&target),
                    ActiveModelWriteMode::Replace,
                    Some(participant),
                    None,
                    Some(TransactionCorrelation::ModelSelection {
                        selection_id,
                        session_id,
                    }),
                )
            };
            let mut collected = Vec::new();
            let recovered = recover_effective_default_journals_blocking(
                &db_for_blocking,
                &cwd_for_blocking,
                &mut collected,
            )
            .map(|()| collected);
            (result, recovered)
        })
        .await
        .unwrap();

        let result = result.expect("session+default transaction commits");
        assert_eq!(
            result
                .selection
                .as_ref()
                .map(|active| active.model.as_str()),
            Some("b")
        );
        let loaded = db.get_session(session_id).await.unwrap().unwrap();
        assert_eq!(loaded.provider.as_deref(), Some("new"));
        assert_eq!(loaded.model.as_deref(), Some("b"));
        assert_eq!(
            loaded.active_model_revision, 1,
            "the guarded CAS advanced exactly once"
        );
        assert_eq!(
            crate::config::providers::ConfigDoc::load_effective(&cwd)
                .active_model
                .map(|active| active.model),
            Some("b".to_string())
        );
        assert!(
            recovered
                .expect("a converged transaction leaves nothing")
                .is_empty(),
            "recovery after a clean commit must be a no-op"
        );
    }
}
