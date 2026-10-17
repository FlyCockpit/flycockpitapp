//! The single owner of one session's accumulated egress redaction table.
//!
//! Every write to a session's accumulated table goes through one
//! [`SessionRedactionOwner`]:
//! - sealed adoption, contained-leak install, approved secret files and the
//!   shell output backstop's observed values;
//! - per-turn refresh unions (driver and session worker);
//! - trusted-child capture.
//!
//! The owner binds three things that must never disagree:
//! - the live [`SharedRedactionTable`];
//! - the async write lock that serializes read → union → persist → swap (H1);
//! - the durable session whose vault item persists the table.
//!
//! Binding the durable owner here, rather than trusting a caller-supplied
//! execution [`Session`], keeps a scheduled fork's registrations in its
//! owner's durable table. A fork runs on a child session, but its leaf hub
//! shares this owner. Without that binding the parent live table would advance
//! while the child's vault item, not the parent's, received the value.
//!
//! The owner also accumulates every observed-output addition (see
//! [`Self::observed_additions`]). Same-turn shell output that only echoes an
//! already-registered value (keyless, encoded) is scrubbed with it even though
//! the tool's own table snapshot predates the registration.

use std::sync::Arc;

use uuid::Uuid;

use crate::daemon::{SharedRedactionTable, current_redaction, set_current_redaction};
use crate::redact::RedactionTable;
use crate::session::Session;

pub struct SessionRedactionOwner {
    table: SharedRedactionTable,
    write_lock: tokio::sync::Mutex<()>,
    /// Session id whose vault item holds this table. A caller-supplied session
    /// is accepted as the durable target only when its id matches.
    owner_id: Uuid,
    /// The bound durable owner (the session worker binds its live `Session`).
    /// When bound, every commit persists here regardless of the caller.
    durable: std::sync::OnceLock<Arc<Session>>,
    /// Union of every observed-output addition committed through this owner
    /// (`None` until the first one: no inert empty table is constructed).
    observed: std::sync::RwLock<Option<Arc<RedactionTable>>>,
    /// Publication generation of the next table this owner publishes; every
    /// published table carries its generation in its live link.
    next_generation: std::sync::atomic::AtomicU64,
    /// Cached enforced view of the current table (for a config opt-out
    /// table), keyed by generation.
    enforced_cache: std::sync::Mutex<Option<(u64, Arc<RedactionTable>)>>,
    /// This owner as the weak live-link source of the tables it publishes.
    weak_self: std::sync::Weak<SessionRedactionOwner>,
}

impl std::fmt::Debug for SessionRedactionOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionRedactionOwner")
            .field("owner_id", &self.owner_id)
            .field("durable_bound", &self.durable.get().is_some())
            .finish_non_exhaustive()
    }
}

impl crate::redact::LiveRedactionSource for SessionRedactionOwner {
    fn newer_view(&self, generation: u64, enforced: bool) -> Option<(u64, Arc<RedactionTable>)> {
        let current = self.current();
        let current_generation = current.live_generation()?;
        if current_generation == generation {
            return None;
        }
        if !enforced || !current.disabled() {
            return Some((current_generation, current));
        }
        let mut cache = self
            .enforced_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((cached_generation, view)) = cache.as_ref()
            && *cached_generation == current_generation
        {
            return Some((current_generation, view.clone()));
        }
        let view = RedactionTable::enforced_arc(current);
        *cache = Some((current_generation, view.clone()));
        Some((current_generation, view))
    }
}

impl SessionRedactionOwner {
    /// An owner whose durable session is identified by `owner_id`. A commit
    /// persists through the caller's session only when its id matches; bind
    /// the session with [`Self::bind_durable_session`] to make it explicit.
    ///
    /// The shared table's current content is re-published as this owner's
    /// first generation (a live-linked copy), so every snapshot taken from
    /// it from now on follows the owner's later commits.
    pub fn new(table: SharedRedactionTable, owner_id: Uuid) -> Arc<Self> {
        let owner = Arc::new_cyclic(|weak_self| Self {
            table,
            write_lock: tokio::sync::Mutex::new(()),
            owner_id,
            durable: std::sync::OnceLock::new(),
            observed: std::sync::RwLock::new(None),
            next_generation: std::sync::atomic::AtomicU64::new(1),
            enforced_cache: std::sync::Mutex::new(None),
            weak_self: weak_self.clone(),
        });
        let initial = (*owner.current()).clone();
        let linked = owner.link(initial);
        set_current_redaction(&owner.table, linked);
        owner
    }

    /// An owner bound to `session` as its durable target.
    pub fn for_session(table: SharedRedactionTable, session: Arc<Session>) -> Arc<Self> {
        let owner = Self::new(table, session.id);
        owner.bind_durable_session(session);
        owner
    }

    /// Bind the durable owner. The first binding wins; a later different
    /// session is ignored (the owner identity never changes).
    pub fn bind_durable_session(&self, session: Arc<Session>) {
        let _ = self.durable.set(session);
    }

    pub fn table(&self) -> &SharedRedactionTable {
        &self.table
    }

    /// The latest committed live table.
    pub fn current(&self) -> Arc<RedactionTable> {
        current_redaction(&self.table)
    }

    /// `table` as this owner's next published generation.
    fn link(&self, table: RedactionTable) -> Arc<RedactionTable> {
        let generation = self
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let source: std::sync::Weak<dyn crate::redact::LiveRedactionSource> =
            self.weak_self.clone();
        Arc::new(table.with_live_link(source, generation))
    }

    /// Every observed-output addition committed so far (values plus their
    /// registered variants), and nothing else from the session table. Applying
    /// it to fresh tool output never changes trusted-model custody for other
    /// sources.
    pub fn observed_additions(&self) -> Option<Arc<RedactionTable>> {
        self.observed
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Acquire the write lock. Every read → union → persist → swap holds the
    /// returned guard for its whole sequence, and reads the base from it.
    pub async fn lock(&self) -> RedactionWriteGuard<'_> {
        RedactionWriteGuard {
            owner: self,
            _guard: self.write_lock.lock().await,
        }
    }
}

/// Proof that the owner's write lock is held.
pub struct RedactionWriteGuard<'a> {
    owner: &'a SessionRedactionOwner,
    _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl RedactionWriteGuard<'_> {
    /// The latest committed table, read under the lock.
    pub fn current(&self) -> Arc<RedactionTable> {
        self.owner.current()
    }

    /// The session whose vault item persists this table. This is the bound
    /// owner, or `caller` when nothing is bound and its id matches.
    /// Otherwise the write is refused: persisting through another session would
    /// advance the live table without its durable owner.
    pub fn durable<'s>(&'s self, caller: &'s Session) -> anyhow::Result<&'s Session> {
        if let Some(bound) = self.owner.durable.get() {
            return Ok(bound.as_ref());
        }
        if caller.id == self.owner.owner_id || caller.live_id() == self.owner.owner_id {
            return Ok(caller);
        }
        anyhow::bail!("redaction table write from a session that does not own the table")
    }

    /// `table` as the owner's next published generation (live-linked), for a
    /// caller that persists it in its own transaction before
    /// [`Self::publish_persisted`].
    pub fn link(&self, table: RedactionTable) -> Arc<RedactionTable> {
        self.owner.link(table)
    }

    /// Persist `table` to the durable owner, then swap it live
    /// (persist-before-swap). On a persist failure nothing is swapped.
    pub fn commit(
        &self,
        caller: &Session,
        table: RedactionTable,
    ) -> anyhow::Result<Arc<RedactionTable>> {
        let table = self.link(table);
        self.durable(caller)?.persist_redaction_table(&table)?;
        self.publish_persisted(table.clone());
        Ok(table)
    }

    /// Swap in a published table.
    pub fn publish_persisted(&self, table: Arc<RedactionTable>) {
        set_current_redaction(&self.owner.table, table);
    }

    /// Record a committed observed-output addition for same-turn consumers.
    pub fn record_observed(&self, addition: &RedactionTable) -> anyhow::Result<()> {
        let mut observed = self
            .owner
            .observed
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next = match observed.as_ref() {
            Some(previous) => previous.union(addition)?,
            None => addition.clone(),
        };
        *observed = Some(Arc::new(next));
        Ok(())
    }
}

/// Refresh one scheduled round's redaction view onto the owner's latest
/// committed table (loop/timer forks and swarm children, which drive `turn`
/// directly rather than through a [`crate::engine::driver::Driver`] round).
/// Registrations an earlier round of the same fork committed reach the next
/// round's tools and egress. Returns `true` when the view changed.
pub(crate) fn adopt_live_redaction_for_round(
    interrupts: &crate::engine::interrupt::InterruptHub,
    providers: &crate::config::providers::ProvidersConfig,
    redact: &mut Arc<RedactionTable>,
    agent: &mut Arc<crate::engine::agent::Agent>,
) -> anyhow::Result<bool> {
    let Some(current) = interrupts.current_live_redaction() else {
        return Ok(false);
    };
    if Arc::ptr_eq(&current, redact) {
        return Ok(false);
    }
    let mut refreshed = (**agent).clone();
    let mut model = (*refreshed.model).clone();
    model.set_redact_table_for_config(providers, current.clone())?;
    refreshed.model = Arc::new(model);
    *agent = Arc::new(refreshed);
    *redact = current;
    Ok(true)
}

#[cfg(test)]
mod codex_r2_successor_probe {
    use super::*;
    #[tokio::test]
    async fn codex_r2_successor_keeps_registration_between_copy_and_adopt() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let initial = Arc::new(RedactionTable::empty());
        session.persist_redaction_table(&initial).unwrap();
        let table: SharedRedactionTable = Arc::new(std::sync::RwLock::new(initial.clone()));
        let hub =
            crate::engine::interrupt::InterruptHub::detached_owning(table.clone(), session.clone());
        let predecessor = session.live_id();
        let successor = Uuid::new_v4();
        session.begin_compaction_successor(successor).unwrap();
        let vault = session.secret_vault().clone();
        let row = db
            .transaction(move |conn| {
                crate::session::lifecycle::copy_vault_session_secrets_on_conn(
                    conn,
                    &vault,
                    predecessor,
                    successor,
                )?;
                crate::db::Db::create_compaction_successor_conn(
                    conn,
                    predecessor,
                    successor,
                    chrono::Utc::now().timestamp_millis(),
                )
            })
            .await
            .unwrap();
        let secret = "NovelSuccessor515Secret78529";
        crate::tools::output_backstop::scrub_command_output(
            &hub,
            &session,
            &initial,
            &crate::config::extended::RedactConfig::default(),
            &format!("DB_SECRET={secret}"),
        )
        .await
        .unwrap();
        assert!(!current_redaction(&table).scrub(secret).contains(secret));
        session
            .adopt_compaction_successor(row.session_id, row.short_id)
            .unwrap();
        let json = crate::session::lifecycle::require_redaction_table_json_from_vault(
            session.secret_vault(),
            successor,
            "reviewer checking successor durable table",
        )
        .unwrap();
        let durable = RedactionTable::from_persisted_json(&json).unwrap();
        assert!(
            !durable.scrub(secret).contains(secret),
            "successful registration missing from resumed successor vault item"
        );
    }
}

#[cfg(test)]
mod codex_r2_cancel_probe {
    use super::*;
    #[tokio::test]
    async fn codex_r2_cancel_queued_write_keeps_live_and_durable_in_sync() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("cancel.db")).unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        assert!(!session.unjournaled_inference_allowed());
        let initial = Arc::new(RedactionTable::empty());
        session.persist_redaction_table(&initial).unwrap();
        let table: SharedRedactionTable = Arc::new(std::sync::RwLock::new(initial.clone()));
        let hub =
            crate::engine::interrupt::InterruptHub::detached_owning(table.clone(), session.clone());
        let stall = db.stall_writer_for_test().unwrap();
        let secret = "NovelCancelled515Secret78529";
        let identity = crate::sealed::identity::SealedRedactionIdentity {
            scope: crate::sealed::identity::SealedScopeKind::Session,
            record_id: None,
            name: crate::sealed::identity::SealedName::canonical("cancel_probe").unwrap(),
            version: 0,
        };
        let mut operation =
            Box::pin(hub.seal_redaction_with_identity(&session, secret.to_owned(), identity));
        assert!(futures::poll!(operation.as_mut()).is_pending());
        drop(operation);
        drop(stall);
        db.write(|_| Ok(())).await.unwrap();
        let json = crate::session::lifecycle::require_redaction_table_json_from_vault(
            session.secret_vault(),
            session.live_id(),
            "reviewer cancellation custody check",
        )
        .unwrap();
        let durable = RedactionTable::from_persisted_json(&json).unwrap();
        let live_scrubbed = !current_redaction(&table).scrub(secret).contains(secret);
        let durable_scrubbed = !durable.scrub(secret).contains(secret);
        assert_eq!(
            live_scrubbed, durable_scrubbed,
            "dropped owner future released lock while queued sealed-table write committed: live={live_scrubbed}, durable={durable_scrubbed}"
        );
    }
}

#[cfg(test)]
mod live_link_tests {
    use super::*;

    // R2 chokepoint: a table snapshot taken from the owner, a table DERIVED
    // from that snapshot (the shape of an outbound guard extended with
    // provider-auth values, a union or an addition) and an OutboundGuard over
    // the snapshot all scrub a value the owner registered AFTER they were
    // taken, so a send path holding any of them cannot render with a stale
    // session table. The derived table keeps its own local literal too.
    #[tokio::test]
    async fn every_snapshot_and_derivation_resolves_to_the_owner_newest_table() {
        let later = "LaterOwner515Value78529";
        let local = "LocalForced515Value78529";
        let table: SharedRedactionTable =
            Arc::new(std::sync::RwLock::new(Arc::new(RedactionTable::empty())));
        let owner = SessionRedactionOwner::new(table, Uuid::new_v4());
        let snapshot = owner.current();
        let derived = Arc::new(
            snapshot
                .with_forced_literal(local.to_owned(), "$forced:live-link-test".to_owned())
                .unwrap(),
        );
        let enforced = Arc::new(snapshot.enforced());
        let outbound = crate::engine::model::OutboundGuard::new(snapshot.clone());
        assert!(snapshot.scrub(later).contains(later), "precondition");
        {
            let guard = owner.lock().await;
            let next = guard.link(
                guard
                    .current()
                    .with_forced_literal(later.to_owned(), "$forced:live-link-later".to_owned())
                    .unwrap(),
            );
            guard.publish_persisted(next);
        }
        for (name, view) in [
            ("snapshot", &snapshot),
            ("derived", &derived),
            ("enforced", &enforced),
        ] {
            assert!(
                !view.scrub(later).contains(later),
                "{name} rendered with a stale session table"
            );
        }
        assert!(
            !outbound.scrub(later).contains(later),
            "outbound guard bypassed the owner"
        );
        assert!(
            !derived.scrub(local).contains(local),
            "derived resolution dropped the table's own literal"
        );
    }
}

#[cfg(test)]
mod security_review_r4 {
    use super::*;
    async fn successor(session: &Session, db: &crate::db::Db) -> (Uuid, String) {
        let predecessor = session.live_id();
        let successor = Uuid::new_v4();
        session.begin_compaction_successor(successor).unwrap();
        let vault = session.secret_vault().clone();
        let row = db
            .transaction(move |conn| {
                crate::session::lifecycle::copy_vault_session_secrets_on_conn(
                    conn,
                    &vault,
                    predecessor,
                    successor,
                )?;
                crate::db::Db::create_compaction_successor_conn(
                    conn,
                    predecessor,
                    successor,
                    chrono::Utc::now().timestamp_millis(),
                )
            })
            .await
            .unwrap();
        (row.session_id, row.short_id)
    }
    fn actual_table(session: &Session, id: Uuid) -> RedactionTable {
        let json = crate::session::lifecycle::require_redaction_table_json_from_vault(
            session.secret_vault(),
            id,
            "r4 direct vault check",
        )
        .unwrap();
        RedactionTable::from_persisted_json(&json).unwrap()
    }
    #[tokio::test]
    async fn r4_inflight_journal_fences_compaction_adoption_after_cancellation() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("r4-inflight.db")).unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let initial = Arc::new(RedactionTable::empty());
        session.persist_redaction_table(&initial).unwrap();
        let hub = crate::engine::interrupt::InterruptHub::detached_owning(
            Arc::new(std::sync::RwLock::new(initial)),
            session.clone(),
        );
        let (id, short) = successor(&session, &db).await;
        let secret = "NovelInflightJournal515Secret78529";
        let stall = db.stall_writer_for_test().unwrap();
        let identity = crate::sealed::identity::SealedRedactionIdentity {
            scope: crate::sealed::identity::SealedScopeKind::Session,
            record_id: None,
            name: crate::sealed::identity::SealedName::canonical("r4inflight").unwrap(),
            version: 0,
        };
        let mut operation =
            Box::pin(hub.seal_redaction_with_identity(&session, secret.to_owned(), identity));
        assert!(futures::poll!(operation.as_mut()).is_pending());
        let error = session
            .adopt_compaction_successor(id, short.clone())
            .unwrap_err();
        assert!(error.to_string().contains("custody is committing"));
        drop(operation);
        let error = session
            .adopt_compaction_successor(id, short.clone())
            .unwrap_err();
        assert!(
            error.to_string().contains("custody is committing"),
            "cancellation released the durable commit fence too early"
        );
        drop(stall);
        db.write(|_| Ok(())).await.unwrap();
        session.adopt_compaction_successor(id, short).unwrap();
        assert_eq!(session.live_id(), id);
        assert!(!actual_table(&session, id).scrub(secret).contains(secret));
    }

    #[tokio::test]
    async fn r4_cancelled_commit_survives_compaction_adoption() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("r4-cancel.db")).unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let initial = Arc::new(RedactionTable::empty());
        session.persist_redaction_table(&initial).unwrap();
        let hub = crate::engine::interrupt::InterruptHub::detached_owning(
            Arc::new(std::sync::RwLock::new(initial)),
            session.clone(),
        );
        let secret = "NovelCancelledCustody51578529";
        let stall = db.stall_writer_for_test().unwrap();
        let identity = crate::sealed::identity::SealedRedactionIdentity {
            scope: crate::sealed::identity::SealedScopeKind::Session,
            record_id: None,
            name: crate::sealed::identity::SealedName::canonical("r4cancel").unwrap(),
            version: 0,
        };
        let mut operation =
            Box::pin(hub.seal_redaction_with_identity(&session, secret.to_owned(), identity));
        assert!(futures::poll!(operation.as_mut()).is_pending());
        drop(operation);
        drop(stall);
        db.write(|_| Ok(())).await.unwrap();
        assert!(
            !actual_table(&session, session.live_id())
                .scrub(secret)
                .contains(secret),
            "precondition: cancelled transaction committed"
        );
        assert!(
            !hub.current_live_redaction()
                .unwrap()
                .scrub(secret)
                .contains(secret),
            "precondition: live publication kept literal"
        );
        let (id, short) = successor(&session, &db).await;
        assert!(
            !actual_table(&session, id).scrub(secret).contains(secret),
            "precondition: copy includes committed literal"
        );
        session.adopt_compaction_successor(id, short).unwrap();
        assert!(
            !actual_table(&session, id).scrub(secret).contains(secret),
            "stale cache overwrote committed successor custody after cancellation"
        );
    }
    #[tokio::test]
    async fn r4_retarget_failure_cannot_adopt_unprotected_successor() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let initial = Arc::new(RedactionTable::empty());
        session.persist_redaction_table(&initial).unwrap();
        let hub = crate::engine::interrupt::InterruptHub::detached_owning(
            Arc::new(std::sync::RwLock::new(initial.clone())),
            session.clone(),
        );
        let (id, short) = successor(&session, &db).await;
        let secret = "NovelRetarget515Secret78529";
        crate::tools::output_backstop::scrub_command_output(
            &hub,
            &session,
            &initial,
            &Default::default(),
            &format!("DB_SECRET={secret}"),
        )
        .await
        .unwrap();
        crate::session::lifecycle::fail_next_redaction_vault_write_for_test();
        let adoption = session.adopt_compaction_successor(id, short.clone());
        assert!(adoption.is_err(), "failed transfer must refuse adoption");
        assert!(
            !crate::session::lifecycle::redaction_vault_write_failure_armed_for_test(),
            "precondition: retarget persist failed"
        );
        assert!(
            session.live_id() != id || !actual_table(&session, id).scrub(secret).contains(secret),
            "failed retarget silently adopted successor without a successful I2 registration"
        );
        session.adopt_compaction_successor(id, short).unwrap();
        assert_eq!(session.live_id(), id);
        assert!(!actual_table(&session, id).scrub(secret).contains(secret));
    }
}

#[cfg(test)]
mod independent_security_review_r5_successor {
    use super::*;

    #[tokio::test]
    async fn review_r5_failed_retarget_cannot_resume_published_successor_without_registration() {
        let tmp = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&tmp.path().join("retarget-resume.db")).unwrap();
        let parent = Arc::new(
            Session::create_for_test(
                db.clone(),
                tmp.path().to_path_buf(),
                "Build",
                crate::session::test_redaction_key_resolver(),
            )
            .unwrap(),
        );
        let initial = Arc::new(RedactionTable::empty());
        parent.persist_redaction_table(&initial).unwrap();
        let hub = crate::engine::interrupt::InterruptHub::detached_owning(
            Arc::new(std::sync::RwLock::new(initial.clone())),
            parent.clone(),
        );
        let predecessor = parent.live_id();
        let successor = uuid::Uuid::new_v4();
        let secret = "NovelAfterCopyRegistration515Review5";
        crate::tools::output_backstop::scrub_command_output(
            &hub,
            &parent,
            &initial,
            &Default::default(),
            &format!("PASSWORD={secret}"),
        )
        .await
        .unwrap();
        assert!(
            !parent
                .persisted_redaction_table()
                .unwrap()
                .unwrap()
                .scrub(secret)
                .contains(secret)
        );
        crate::session::lifecycle::fail_next_redaction_vault_write_for_test();
        // Exercise the sole production publication boundary, which replaced
        // the old copy -> published edge -> fallible adoption sequence.
        let error = parent
            .publish_compaction_successor(successor)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("injected redaction vault write failure"));
        assert_eq!(parent.live_id(), predecessor);
        assert!(db.get_session(successor).await.unwrap().is_none());
        assert!(
            db.get_session(predecessor)
                .await
                .unwrap()
                .unwrap()
                .ended_at_unix_ms
                .is_none()
        );
        let resumed = Session::resume_with_test_workspace_root(
            db.clone(),
            predecessor,
            parent.redaction_key_resolver().clone(),
            parent.secret_vault().clone(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(resumed.live_id(), predecessor);
        assert!(
            !resumed
                .persisted_redaction_table()
                .unwrap()
                .unwrap()
                .scrub(secret)
                .contains(secret),
            "failed transition lost successfully registered custody on resume"
        );
        // Inverse: a later successful transition must still work and include
        // every registration in the actual successor vault and canonical resume.
        parent
            .publish_compaction_successor(successor)
            .await
            .unwrap();
        let resumed = Session::resume_with_test_workspace_root(
            db,
            predecessor,
            parent.redaction_key_resolver().clone(),
            parent.secret_vault().clone(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(resumed.live_id(), successor);
        assert!(
            !resumed
                .persisted_redaction_table()
                .unwrap()
                .unwrap()
                .scrub(secret)
                .contains(secret),
            "published successor is missing a successful registration"
        );
    }
}
