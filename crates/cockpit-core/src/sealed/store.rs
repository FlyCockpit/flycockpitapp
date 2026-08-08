//! Owner-only sealed-value lifecycle and safe inventory.
//!
//! Every entry point here demands an [`OwnerAuthority`]. Agents and remote
//! clients cannot create, inventory, rotate, delete, grant, revoke, or recover
//! persistent literals, because they cannot obtain that token.
//!
//! Session scope is a single store (SQLite) and its lifecycle is one
//! transaction. Project and Global scope span SQLite *and* the sealed
//! compartment, so their lifecycle is a crash-resumable prepared/committed
//! saga. The staged steps are separate methods precisely so a test can stop
//! between any two of them and then drive [`SealedValueDirectory::recover`].
//!
//! `/sealed` transport, command grammar, recovery UX, and immutable
//! action-instance administration belong to `sealed-value-owner-management`.
//! This module exposes safe metadata and exact lifecycle operations only.

use anyhow::{Context, Result, bail};
use cockpit_db::db::Db;
use cockpit_db::db::sealed_scope::{
    NewSealedActionGrant, NewSealedValueRecord, SealedSagaKind, SealedSagaPhase, SealedSagaRow,
    SealedScopeKind, SealedValueRecordRow,
};
use uuid::Uuid;

use super::action::{OwnerAuthority, SealedActionId, SealedActionRevision};
use super::compartment::{SealedCompartment, SealedCompartmentKey, SealedLiteral};
use super::identity::{
    SealedDescription, SealedName, SealedProjectKey, SealedRecordId, SealedScopeRef,
};

/// Safe metadata for one sealed value. This is the entire Owner inventory
/// projection: canonical identity, safe description, and lifecycle stamps.
/// It carries no literal, no compartment locator, and no grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedValueSummary {
    pub record_id: SealedRecordId,
    pub scope: SealedScopeKind,
    pub name: SealedName,
    pub description: SealedDescription,
    pub owner_principal: String,
    pub version: u32,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl SealedValueSummary {
    fn from_row(row: &SealedValueRecordRow) -> Result<Self> {
        Ok(Self {
            record_id: SealedRecordId::parse(&row.record_id)?,
            scope: row.scope,
            name: SealedName::canonical(&row.name)?,
            description: SealedDescription::parse(&row.description)?,
            owner_principal: row.owner_principal.clone(),
            version: u32::try_from(row.active_version).unwrap_or(0),
            created_at_ms: row.created_at_ms,
            updated_at_ms: row.updated_at_ms,
        })
    }
}

/// What the Owner supplies to create a sealed value.
#[derive(Debug, Clone)]
pub struct CreateSealedValue {
    pub scope: SealedScopeRef,
    pub name: SealedName,
    pub description: SealedDescription,
    pub owner_principal: String,
}

/// What the Owner supplies to issue one exact action grant.
#[derive(Debug, Clone)]
pub struct IssueSealedGrant {
    pub record_id: SealedRecordId,
    pub value_version: u32,
    pub project_key: SealedProjectKey,
    pub session_id: Uuid,
    pub session_generation: u64,
    pub action_id: SealedActionId,
    pub action_revision: SealedActionRevision,
    pub issued_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

/// A handle to an issued grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedGrantHandle {
    pub grant_id: Uuid,
}

/// An in-flight cross-store lifecycle saga.
#[derive(Debug, Clone)]
pub struct SealedSagaTicket {
    pub op_id: String,
    pub record_id: SealedRecordId,
    pub kind: SealedSagaKind,
    pub target_version: u32,
    pub staged_key: Option<SealedCompartmentKey>,
}

/// What [`SealedValueDirectory::recover`] resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealedRecoveryReport {
    /// Sagas undone: an interrupted create or rotate.
    pub rolled_back: Vec<String>,
    /// Sagas completed: an interrupted delete, or any committed saga whose
    /// compartment cleanup had not yet run.
    pub rolled_forward: Vec<String>,
}

impl SealedRecoveryReport {
    pub fn is_empty(&self) -> bool {
        self.rolled_back.is_empty() && self.rolled_forward.is_empty()
    }
}

/// The Owner-facing sealed-value store.
#[derive(Debug, Clone)]
pub struct SealedValueDirectory {
    db: Db,
    compartment: SealedCompartment,
}

impl SealedValueDirectory {
    pub fn new(db: Db, compartment: SealedCompartment) -> Self {
        Self { db, compartment }
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn compartment(&self) -> &SealedCompartment {
        &self.compartment
    }

    /// Owner-only safe inventory for one scope.
    ///
    /// This is the only listing surface *in the scoped subsystem*, it is
    /// unreachable without Owner authority, and there is no count, prefix,
    /// existence, or status variant of it.
    ///
    /// It is deliberately not claimed to be the only listing surface anywhere
    /// in the sealed feature, because it is not: the daemon's
    /// `ListSealedValues` request still reads the legacy
    /// `Db::list_sealed_value_metadata`. That surface is also `owner_only`, so
    /// the authority property holds across both — but a session-scope scoped
    /// value is dual-written and therefore visible through the legacy listing
    /// too, and project- and global-scope values are not visible through it at
    /// all. Anything reasoning about "every way a sealed value can be
    /// enumerated" has to account for both.
    pub async fn inventory(
        &self,
        _owner: OwnerAuthority,
        scope: &SealedScopeRef,
    ) -> Result<Vec<SealedValueSummary>> {
        let rows = self
            .db
            .sealed_value_inventory(scope.kind(), scope.scope_key())
            .await?;
        rows.iter().map(SealedValueSummary::from_row).collect()
    }

    /// Exact Owner lookup of one record's safe metadata.
    pub async fn summary(
        &self,
        _owner: OwnerAuthority,
        record_id: SealedRecordId,
    ) -> Result<Option<SealedValueSummary>> {
        let Some(row) = self.db.sealed_value_record(record_id.to_string()).await? else {
            return Ok(None);
        };
        Ok(Some(SealedValueSummary::from_row(&row)?))
    }

    /// Create a sealed value, running the whole lifecycle to completion.
    pub async fn create(
        &self,
        owner: OwnerAuthority,
        request: CreateSealedValue,
        literal: SealedLiteral,
        now_ms: i64,
    ) -> Result<SealedValueSummary> {
        if !request.scope.kind().is_persistent_compartment() {
            return self
                .create_session_scoped(owner, request, literal, now_ms)
                .await;
        }
        let ticket = self.prepare_create(owner, request, now_ms).await?;
        self.stage_literal(&ticket, literal)?;
        let summary = self.commit_create(owner, &ticket, now_ms).await?;
        self.finish_saga(owner, &ticket).await?;
        Ok(summary)
    }

    /// Session scope: one store, one transaction, no saga.
    async fn create_session_scoped(
        &self,
        _owner: OwnerAuthority,
        request: CreateSealedValue,
        literal: SealedLiteral,
        now_ms: i64,
    ) -> Result<SealedValueSummary> {
        let record = self.new_record(&request, now_ms);
        let row = self
            .db
            .create_session_sealed_value(
                record,
                literal.expose_for_redaction().to_string(),
                request.description.as_str().to_string(),
                "owner".to_string(),
            )
            .await?;
        SealedValueSummary::from_row(&row)
    }

    /// Stage a new compartment-backed record. Not resolvable yet.
    pub async fn prepare_create(
        &self,
        _owner: OwnerAuthority,
        request: CreateSealedValue,
        now_ms: i64,
    ) -> Result<SealedSagaTicket> {
        if !request.scope.kind().is_persistent_compartment() {
            bail!("session-scope sealed values are created in a single transaction");
        }
        let record = self.new_record(&request, now_ms);
        let record_id = SealedRecordId::parse(&record.record_id)?;
        let op_id = Uuid::new_v4().to_string();
        let staged = SealedCompartmentKey::generate();
        self.db
            .prepare_sealed_value_create(record, op_id.clone(), Some(staged.as_str().to_string()))
            .await?;
        Ok(SealedSagaTicket {
            op_id,
            record_id,
            kind: SealedSagaKind::Create,
            target_version: 1,
            staged_key: Some(staged),
        })
    }

    /// Write the literal to the staged compartment locator. The record is
    /// still not resolvable after this.
    pub fn stage_literal(&self, ticket: &SealedSagaTicket, literal: SealedLiteral) -> Result<()> {
        let key = ticket
            .staged_key
            .as_ref()
            .context("saga stages no compartment locator")?;
        self.compartment.put(key, &literal)
    }

    /// Publish the staged create. The record becomes resolvable here.
    pub async fn commit_create(
        &self,
        _owner: OwnerAuthority,
        ticket: &SealedSagaTicket,
        now_ms: i64,
    ) -> Result<SealedValueSummary> {
        let key = ticket
            .staged_key
            .as_ref()
            .context("saga stages no compartment locator")?;
        // Publishing a record whose locator holds nothing would produce a
        // resolvable value that denies forever behind the content-free
        // denial — undiagnosable in the field. The staged steps are public so
        // recovery tests can stop between them, so this cannot be left to
        // `create()` always calling `stage_literal`. An exact-key lookup of a
        // locator the Owner lifecycle just minted is not an enumeration path.
        if self.compartment.get_exact(key)?.is_none() {
            bail!("refusing to publish a sealed value whose literal was never staged");
        }
        let row = self
            .db
            .commit_sealed_value_create(
                ticket.record_id.to_string(),
                Some(key.as_str().to_string()),
                now_ms,
            )
            .await?;
        SealedValueSummary::from_row(&row)
    }

    /// Rotate a sealed value, running the whole lifecycle to completion.
    ///
    /// Rotation always creates a new key and a monotonically increasing
    /// version; it never overwrites the previous version in place.
    pub async fn rotate(
        &self,
        owner: OwnerAuthority,
        record_id: SealedRecordId,
        literal: SealedLiteral,
        now_ms: i64,
    ) -> Result<SealedValueSummary> {
        let row = self
            .db
            .sealed_value_record(record_id.to_string())
            .await?
            .context("sealed value record does not exist")?;
        if row.scope == SealedScopeKind::Session {
            let rotated = self
                .db
                .rotate_session_sealed_value(
                    record_id.to_string(),
                    literal.expose_for_redaction().to_string(),
                    now_ms,
                )
                .await?;
            return SealedValueSummary::from_row(&rotated);
        }
        let ticket = self.prepare_rotate(owner, record_id, now_ms).await?;
        self.stage_literal(&ticket, literal)?;
        let summary = self.commit_rotate(owner, &ticket, now_ms).await?;
        // Reclaim the superseded literal before dropping the saga row, so the
        // compartment never accumulates orphaned prior versions.
        self.reclaim_superseded(&ticket.op_id).await?;
        self.finish_saga(owner, &ticket).await?;
        Ok(summary)
    }

    /// Stage a rotation. The previous version stays live until commit.
    pub async fn prepare_rotate(
        &self,
        _owner: OwnerAuthority,
        record_id: SealedRecordId,
        now_ms: i64,
    ) -> Result<SealedSagaTicket> {
        let op_id = Uuid::new_v4().to_string();
        let staged = SealedCompartmentKey::generate();
        let target = self
            .db
            .prepare_sealed_value_rotate(
                record_id.to_string(),
                op_id.clone(),
                staged.as_str().to_string(),
                now_ms,
            )
            .await?;
        Ok(SealedSagaTicket {
            op_id,
            record_id,
            kind: SealedSagaKind::Rotate,
            target_version: u32::try_from(target).unwrap_or(u32::MAX),
            staged_key: Some(staged),
        })
    }

    /// Publish the staged rotation.
    pub async fn commit_rotate(
        &self,
        _owner: OwnerAuthority,
        ticket: &SealedSagaTicket,
        now_ms: i64,
    ) -> Result<SealedValueSummary> {
        let key = ticket
            .staged_key
            .as_ref()
            .context("saga stages no compartment locator")?;
        if self.compartment.get_exact(key)?.is_none() {
            bail!("refusing to publish a rotation whose literal was never staged");
        }
        let row = self
            .db
            .commit_sealed_value_rotate(ticket.record_id.to_string(), now_ms)
            .await?;
        SealedValueSummary::from_row(&row)
    }

    /// Delete a sealed value, running the whole lifecycle to completion.
    pub async fn delete(
        &self,
        owner: OwnerAuthority,
        record_id: SealedRecordId,
        now_ms: i64,
    ) -> Result<bool> {
        let Some(row) = self.db.sealed_value_record(record_id.to_string()).await? else {
            return Ok(false);
        };
        if row.scope == SealedScopeKind::Session {
            return self
                .db
                .delete_session_sealed_value(record_id.to_string(), now_ms)
                .await;
        }
        let ticket = self.prepare_delete(owner, record_id, now_ms).await?;
        self.commit_delete(owner, &ticket, now_ms).await?;
        self.reclaim_superseded(&ticket.op_id).await?;
        self.finish_saga(owner, &ticket).await?;
        Ok(true)
    }

    /// Stage a delete. Use is denied from this instant, before the row or the
    /// literal is reclaimed.
    pub async fn prepare_delete(
        &self,
        _owner: OwnerAuthority,
        record_id: SealedRecordId,
        now_ms: i64,
    ) -> Result<SealedSagaTicket> {
        let op_id = Uuid::new_v4().to_string();
        let saga = self
            .db
            .prepare_sealed_value_delete(record_id.to_string(), op_id.clone(), now_ms)
            .await?
            .context("sealed value record does not exist")?;
        Ok(SealedSagaTicket {
            op_id: saga.op_id,
            record_id,
            kind: SealedSagaKind::Delete,
            target_version: u32::try_from(saga.target_version).unwrap_or(0),
            staged_key: None,
        })
    }

    /// Reclaim the record row.
    pub async fn commit_delete(
        &self,
        _owner: OwnerAuthority,
        ticket: &SealedSagaTicket,
        now_ms: i64,
    ) -> Result<bool> {
        self.db
            .commit_sealed_value_delete(ticket.record_id.to_string(), now_ms)
            .await
    }

    /// Drop a resolved saga row once its compartment cleanup has run.
    pub async fn finish_saga(
        &self,
        _owner: OwnerAuthority,
        ticket: &SealedSagaTicket,
    ) -> Result<()> {
        self.db.finish_sealed_value_saga(ticket.op_id.clone()).await
    }

    /// Grant one Global sealed value to one canonical project.
    pub async fn grant_global_to_project(
        &self,
        _owner: OwnerAuthority,
        record_id: SealedRecordId,
        project_key: &SealedProjectKey,
        now_ms: i64,
    ) -> Result<()> {
        let row = self
            .db
            .sealed_value_record(record_id.to_string())
            .await?
            .context("sealed value record does not exist")?;
        if row.scope != SealedScopeKind::Global {
            bail!("only a global sealed value is granted to a project");
        }
        self.db
            .grant_sealed_global_to_project(
                record_id.to_string(),
                project_key.as_str().to_string(),
                now_ms,
            )
            .await
    }

    /// Issue one exact action grant.
    pub async fn issue_action_grant(
        &self,
        _owner: OwnerAuthority,
        request: IssueSealedGrant,
    ) -> Result<SealedGrantHandle> {
        let grant_id = Uuid::new_v4();
        self.db
            .issue_sealed_action_grant(NewSealedActionGrant {
                grant_id: grant_id.to_string(),
                record_id: request.record_id.to_string(),
                value_version: i64::from(request.value_version),
                project_key: request.project_key.as_str().to_string(),
                session_id: request.session_id.to_string(),
                session_generation: request.session_generation as i64,
                action_id: request.action_id.as_str().to_string(),
                action_revision: i64::from(request.action_revision.get()),
                issued_at_ms: request.issued_at_ms,
                expires_at_ms: request.expires_at_ms,
            })
            .await?;
        Ok(SealedGrantHandle { grant_id })
    }

    /// Revoke one grant. Revocation is one-way and denies use immediately.
    pub async fn revoke_action_grant(
        &self,
        _owner: OwnerAuthority,
        handle: SealedGrantHandle,
        now_ms: i64,
    ) -> Result<bool> {
        self.db
            .revoke_sealed_action_grant(handle.grant_id.to_string(), now_ms)
            .await
    }

    /// Resolve every unresolved cross-store saga.
    ///
    /// Idempotent and safe to run at every daemon start. `create` and `rotate`
    /// roll back to their previous state; `delete` and every committed saga
    /// roll forward. In no case does a partially applied lifecycle become
    /// resolvable.
    pub async fn recover(&self, owner: OwnerAuthority) -> Result<SealedRecoveryReport> {
        // A crash between compartment write and rename strands a temp file
        // holding raw plaintext that no saga references. Reclaim those first.
        self.compartment.reclaim_stale_temporaries()?;

        let sagas = self.db.unresolved_sealed_value_sagas().await?;
        let mut report = SealedRecoveryReport::default();
        for saga in sagas {
            if saga.phase == SealedSagaPhase::Committed {
                self.resolve_committed(&saga).await?;
                report.rolled_forward.push(saga.op_id);
                continue;
            }
            match saga.kind {
                SealedSagaKind::Create | SealedSagaKind::Rotate => {
                    self.discard_staged(&saga)?;
                    self.db
                        .rollback_sealed_value_saga(saga.record_id.clone())
                        .await?;
                    report.rolled_back.push(saga.op_id);
                }
                SealedSagaKind::Delete => {
                    let ticket = SealedSagaTicket {
                        op_id: saga.op_id.clone(),
                        record_id: SealedRecordId::parse(&saga.record_id)?,
                        kind: SealedSagaKind::Delete,
                        target_version: u32::try_from(saga.target_version).unwrap_or(0),
                        staged_key: None,
                    };
                    self.commit_delete(owner, &ticket, saga.updated_at_ms)
                        .await?;
                    self.reclaim_saga_keys(&saga)?;
                    self.db.finish_sealed_value_saga(saga.op_id.clone()).await?;
                    report.rolled_forward.push(saga.op_id);
                }
            }
        }
        Ok(report)
    }

    async fn resolve_committed(&self, saga: &SealedSagaRow) -> Result<()> {
        if saga.kind == SealedSagaKind::Delete {
            self.db
                .commit_sealed_value_delete(saga.record_id.clone(), saga.updated_at_ms)
                .await?;
        }
        self.reclaim_saga_keys(saga)?;
        self.db.finish_sealed_value_saga(saga.op_id.clone()).await
    }

    /// Discard a staged-but-never-published locator.
    fn discard_staged(&self, saga: &SealedSagaRow) -> Result<()> {
        let Some(raw) = saga.prepared_compartment_key.as_deref() else {
            return Ok(());
        };
        let key = SealedCompartmentKey::parse(raw)?;
        self.compartment.remove(&key)
    }

    async fn reclaim_superseded(&self, op_id: &str) -> Result<()> {
        let sagas = self.db.unresolved_sealed_value_sagas().await?;
        let Some(saga) = sagas.into_iter().find(|saga| saga.op_id == op_id) else {
            return Ok(());
        };
        self.reclaim_saga_keys(&saga)
    }

    fn reclaim_superseded_key(&self, raw: Option<&str>) -> Result<()> {
        let Some(raw) = raw else {
            return Ok(());
        };
        let key = SealedCompartmentKey::parse(raw)?;
        self.compartment.remove(&key)
    }

    /// Reclaim every locator a resolved saga is responsible for.
    ///
    /// The superseded locator always goes. The *staged* locator goes only for
    /// a delete: a delete that converted an in-flight rotation inherits that
    /// rotation's staged plaintext, which nothing else references, so leaving
    /// it would strand a deleted value's literal on disk. For a rotation the
    /// staged locator is the new **live** one and must survive.
    fn reclaim_saga_keys(&self, saga: &SealedSagaRow) -> Result<()> {
        self.reclaim_superseded_key(saga.superseded_compartment_key.as_deref())?;
        if saga.kind == SealedSagaKind::Delete {
            self.reclaim_superseded_key(saga.prepared_compartment_key.as_deref())?;
        }
        Ok(())
    }

    fn new_record(&self, request: &CreateSealedValue, now_ms: i64) -> NewSealedValueRecord {
        NewSealedValueRecord {
            record_id: SealedRecordId::generate().to_string(),
            scope: request.scope.kind(),
            scope_key: request.scope.scope_key(),
            name: request.name.as_str().to_string(),
            description: request.description.as_str().to_string(),
            owner_principal: request.owner_principal.clone(),
            created_at_ms: now_ms,
        }
    }
}
