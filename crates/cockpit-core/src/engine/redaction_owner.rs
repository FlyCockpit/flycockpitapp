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

impl SessionRedactionOwner {
    /// An owner whose durable session is identified by `owner_id`. A commit
    /// persists through the caller's session only when its id matches; bind
    /// the session with [`Self::bind_durable_session`] to make it explicit.
    pub fn new(table: SharedRedactionTable, owner_id: Uuid) -> Self {
        Self {
            table,
            write_lock: tokio::sync::Mutex::new(()),
            owner_id,
            durable: std::sync::OnceLock::new(),
            observed: std::sync::RwLock::new(None),
        }
    }

    /// An owner bound to `session` as its durable target.
    pub fn for_session(table: SharedRedactionTable, session: Arc<Session>) -> Self {
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

    /// Persist `table` to the durable owner, then swap it live
    /// (persist-before-swap). On a persist failure nothing is swapped.
    pub fn commit(
        &self,
        caller: &Session,
        table: RedactionTable,
    ) -> anyhow::Result<Arc<RedactionTable>> {
        let table = Arc::new(table);
        self.durable(caller)?.persist_redaction_table(&table)?;
        self.publish_persisted(table.clone());
        Ok(table)
    }

    /// Swap in a table the caller already persisted to [`Self::durable`] in
    /// its own transaction (journaled sealed adoption, trusted capture).
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
) -> bool {
    let Some(current) = interrupts.current_live_redaction() else {
        return false;
    };
    if Arc::ptr_eq(&current, redact) {
        return false;
    }
    let mut refreshed = (**agent).clone();
    let mut model = (*refreshed.model).clone();
    model.set_redact_table_for_config(providers, current.clone());
    refreshed.model = Arc::new(model);
    *agent = Arc::new(refreshed);
    *redact = current;
    true
}
