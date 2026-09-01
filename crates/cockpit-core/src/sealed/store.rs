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

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use cockpit_db::db::Db;
use cockpit_db::db::sealed_scope::{
    NewSealedActionGrant, NewSealedValueRecord, SealedSagaKind, SealedSagaPhase, SealedSagaRow,
    SealedScopeKind, SealedValueRecordRow, create_session_sealed_value_conn,
    promote_session_sealed_value_conn, rotate_session_sealed_value_conn,
};
use cockpit_db::secret_vault::SecretVaultKind;
use uuid::Uuid;

use crate::redact::protected_redaction_history::{
    ProtectedLiteral, ProtectedRedactionHistory, RedactionHistorySource, RedactionKeyResolver,
    append_and_attach_conn,
};

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
///
/// This store persists sealed-value **rows** and drives the cross-store saga.
/// A **session-scope** create/rotate owns a real `session_id` and adopts the
/// literal into that session (the sealed row is itself the durability event),
/// so it journals a `Sealed` protected-history row on adoption — in the same
/// transaction that persists the sealed row, with zero artifact refs (decision
/// 10.1). Zero refs is explicitly allowed here precisely because the adoption
/// is the durability event; the orphan-row prohibition applies only to the
/// **compartment-backed** `commit_create` / `commit_rotate`, which have no
/// session and therefore journal nothing.
///
/// The protected-history key resolver is installed by the session-facing caller
/// that owns the session ([`Self::with_redaction_resolver`]). Because a
/// session-scope adoption must never regress to an unjournaled persist under
/// partial wiring, session-scope create/rotate **fail closed** when no resolver
/// is installed (decision 16), rather than silently skipping the journal.
#[derive(Clone)]
pub struct SealedValueDirectory {
    db: Db,
    compartment: SealedCompartment,
    /// Protected redaction-history key resolver, installed by the session-facing
    /// caller that owns the session (decision 10.1). The session-scoped
    /// create/rotate paths journal the adopted sealed literal into protected
    /// history in the same transaction that persists the sealed row. `None` only
    /// in fixtures that never introduce a literal into a live session; a
    /// session-scope create/rotate with `None` fails closed rather than persist
    /// unjournaled (decision 16).
    redaction_resolver: Option<Arc<dyn RedactionKeyResolver>>,
}

impl std::fmt::Debug for SealedValueDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedValueDirectory")
            .field("compartment", &self.compartment)
            .field(
                "redaction_resolver",
                &self.redaction_resolver.as_ref().map(|_| "<resolver>"),
            )
            .finish_non_exhaustive()
    }
}

impl SealedValueDirectory {
    pub fn new(db: Db, compartment: SealedCompartment) -> Self {
        Self {
            db,
            compartment,
            redaction_resolver: None,
        }
    }

    /// Install the protected redaction-history key resolver so session-scoped
    /// create/rotate journal the adopted sealed literal on session adoption
    /// (decision 10.1). The session-facing caller that owns the session's
    /// resolver threads it here.
    pub fn with_redaction_resolver(mut self, resolver: Arc<dyn RedactionKeyResolver>) -> Self {
        self.redaction_resolver = Some(resolver);
        self
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn compartment(&self) -> &SealedCompartment {
        &self.compartment
    }

    /// Resolve a session-scoped sealed literal for a claimed version.
    ///
    /// The version fence is a single SQLite snapshot (`active_version` must
    /// equal `claimed_version`). The plaintext is then unwrapped from the
    /// wrap-key vault item for that exact version, so a rotate that advances
    /// the row cannot hand a stale claim the newer literal.
    pub async fn session_literal_for_action(
        &self,
        _owner: OwnerAuthority,
        record_id: String,
        claimed_version: i64,
    ) -> Result<Option<String>> {
        let Some((scope_key, name)) = self
            .db
            .sealed_session_version_fence(record_id, claimed_version)
            .await?
        else {
            return Ok(None);
        };
        let vault = self
            .compartment
            .vault()
            .context("session sealed literal resolve requires a vault-backed compartment")?;
        let item_id = crate::secure_key::session_sealed_item_id(&scope_key, &name, claimed_version);
        match vault.get_item(SecretVaultKind::SessionSealedValue, &item_id) {
            Ok(secret) => {
                let literal = String::from_utf8(secret.as_slice().to_vec())
                    .context("session sealed vault item is not UTF-8")?;
                Ok(Some(literal))
            }
            Err(crate::secure_key::SecureKeyError::NotFound(_)) => Ok(None),
            Err(error) => Err(anyhow::anyhow!(
                "unwrapping session sealed vault item: {error}"
            )),
        }
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

    /// Owner-only inventory as raw record rows, for the sealed-owner dispatch
    /// projection. `scope = Some` narrows to one scope; `None` returns every live
    /// record across all scopes (machine-wide). Unlike [`Self::inventory`], the
    /// rows keep their own scope key, so a fully-qualified wire inventory item
    /// can be projected without re-deriving the key from the query.
    pub async fn inventory_records(
        &self,
        _owner: OwnerAuthority,
        scope: Option<&SealedScopeRef>,
    ) -> Result<Vec<SealedValueRecordRow>> {
        match scope {
            Some(scope) => {
                self.db
                    .sealed_value_inventory(scope.kind(), scope.scope_key())
                    .await
            }
            None => self.db.list_all_sealed_value_records().await,
        }
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
        if request.scope.kind() == SealedScopeKind::KnowledgeBase {
            bail!(
                "knowledge-base sealed values are created through KnowledgeBaseSealedStore, not the owner action-grant directory"
            );
        }
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
    ///
    /// This session-OWNING path adopts the literal into a live session (the
    /// sealed row is itself the durability event), so it journals a `Sealed`
    /// protected-history row on adoption in the SAME transaction that persists
    /// the sealed row, carrying the typed identity (new `record_id`, version 1)
    /// and zero artifact refs (decision 10.1). A failure of the prepare or the
    /// transaction rolls the whole create back, so a sealed value never persists
    /// half-journaled. Fails closed when no resolver is installed rather than
    /// regress to an unjournaled persist (decision 16).
    async fn create_session_scoped(
        &self,
        _owner: OwnerAuthority,
        request: CreateSealedValue,
        literal: SealedLiteral,
        now_ms: i64,
    ) -> Result<SealedValueSummary> {
        let record = self.new_record(&request, now_ms);
        let reason = request.description.as_str().to_string();
        let origin = "owner".to_string();
        let literal_str = literal.expose_for_redaction().to_string();

        // A session-scope create adopts the literal into a live session, so it
        // MUST journal. Fail closed if no resolver is installed rather than
        // persist a sealed literal unjournaled (decision 16 — no "skip when
        // missing" fork).
        let resolver = self.redaction_resolver.as_ref().context(
            "session-scoped sealed create requires an installed redaction-history resolver to \
             journal the adoption (decision 10.1); refusing to persist a sealed literal \
             unjournaled",
        )?;

        // Session-scope create installs the sealed literal into a live session at
        // version 1; journal it on adoption. `scope_key` is the session id
        // string. Prepare off the DB thread (async key load + AEAD): a failure
        // here rolls nothing back because nothing has persisted yet (fail
        // closed).
        let session_id = record.scope_key.clone();
        let protected = ProtectedLiteral::new(
            literal_str.clone(),
            RedactionHistorySource::Sealed,
            Some(record.record_id.clone()),
            Some(1),
        )?;
        let history = ProtectedRedactionHistory::new(&self.db, resolver.as_ref());
        let prepared = history.prepare_append(&session_id, protected).await?;

        // Persist the sealed row and journal the append in one transaction: a
        // failure of either rolls back both, so a sealed value never persists
        // half-journaled. Zero artifact refs — the session-scope adoption is
        // itself the durability event.
        let vault = self.compartment.vault().cloned().ok_or_else(|| {
            anyhow::anyhow!("session sealed create requires a vault-backed compartment")
        })?;
        let item_id = crate::secure_key::session_sealed_item_id(&record.scope_key, &record.name, 1);
        let row = self
            .db
            .transaction(move |conn| {
                let row = create_session_sealed_value_conn(
                    conn,
                    &record,
                    &literal_str,
                    &reason,
                    &origin,
                )?;
                vault
                    .put_item_on_conn(
                        conn,
                        SecretVaultKind::SessionSealedValue,
                        &item_id,
                        literal_str.as_bytes(),
                    )
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                append_and_attach_conn(conn, &prepared, &[])?;
                Ok(row)
            })
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
        if row.scope == SealedScopeKind::KnowledgeBase {
            bail!("knowledge-base sealed values do not support owner action rotation");
        }
        if row.scope == SealedScopeKind::Session {
            // A session rotate adopts a new literal into a live session, so it
            // MUST journal the adoption in the same transaction that persists the
            // rotated sealed row (decision 10.1). Fail closed if no resolver is
            // installed rather than persist an unjournaled rotation (decision 16).
            let literal_str = literal.expose_for_redaction().to_string();

            let resolver = self.redaction_resolver.as_ref().context(
                "session-scoped sealed rotate requires an installed redaction-history resolver to \
                 journal the adoption (decision 10.1); refusing to persist a rotated sealed \
                 literal unjournaled",
            )?;

            // `new_version` here is a *prediction* from a read taken before the
            // write lock: the pre-`prepare_append` `active_version + 1`. The AEAD
            // binds only session id / source / key version, not the sealed
            // version, so the prediction only decides the `sealed_version` column
            // — which the transaction below re-validates against the authoritative
            // committed version (F8).
            let session_id = row.scope_key.clone();
            let new_version = row.active_version + 1;
            let protected = ProtectedLiteral::new(
                literal_str.clone(),
                RedactionHistorySource::Sealed,
                Some(record_id.to_string()),
                Some(new_version),
            )?;
            let history = ProtectedRedactionHistory::new(&self.db, resolver.as_ref());
            let prepared = history.prepare_append(&session_id, protected).await?;

            // One transaction: the rotate and the journal append commit together
            // or roll back together. Zero artifact refs — the adoption is the
            // durability event.
            //
            // F8 — concurrent-rotation version race. `rotate_session_sealed_value_conn`
            // derives the new `active_version` authoritatively INSIDE this
            // transaction (SQLite serializes writers), so two concurrent rotations
            // that both predicted v2 cannot both commit v2: the loser's committed
            // row advances to v3 while its prepared journal still carries v2.
            // Assert the committed version equals the journaled `new_version` and
            // fail closed (roll back the whole rotation) on any mismatch, so the
            // history row can never carry a stale version. The loser retries
            // against the advanced row.
            let record_id_str = record_id.to_string();
            let vault = self.compartment.vault().cloned().ok_or_else(|| {
                anyhow::anyhow!("session sealed rotate requires a vault-backed compartment")
            })?;
            let session_key = row.scope_key.clone();
            let name = row.name.clone();
            let rotated = self
                .db
                .transaction(move |conn| {
                    let rotated = rotate_session_sealed_value_conn(
                        conn,
                        &record_id_str,
                        &literal_str,
                        now_ms,
                    )?;
                    if rotated.active_version != new_version {
                        bail!(
                            "concurrent sealed rotation: journaled version {new_version} does \
                             not match the committed version {}; rolling back so protected \
                             history never carries a stale sealed version",
                            rotated.active_version
                        );
                    }
                    let item_id = crate::secure_key::session_sealed_item_id(
                        &session_key,
                        &name,
                        rotated.active_version,
                    );
                    vault
                        .put_item_on_conn(
                            conn,
                            SecretVaultKind::SessionSealedValue,
                            &item_id,
                            literal_str.as_bytes(),
                        )
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    append_and_attach_conn(conn, &prepared, &[])?;
                    Ok(rotated)
                })
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

    /// Rotate a sealed value, fencing the operation on an exact expected
    /// version so the version check is **atomic with the mutation**.
    ///
    /// This is the Owner-channel write path: a capability minted at version `N`
    /// must overwrite exactly version `N`. If a concurrent rotation advanced the
    /// record past `N` between mint and apply, this returns `Err` and performs
    /// no write — the version fence lives inside the authoritative store
    /// operation, not in a separate read-then-act, so no interleaving can slip a
    /// post-race version under the capability.
    ///
    /// * Session scope: the version bump happens inside one transaction; the
    ///   committed `active_version` is required to equal `expected + 1` (i.e. we
    ///   rotated *from* `expected`), else the whole transaction rolls back.
    /// * Compartment scope: `prepare_rotate` reads `active_version` and inserts
    ///   the lifecycle saga in one transaction, and the saga-in-flight guard
    ///   blocks any other rotation until this one finishes — so `active_version`
    ///   cannot move between prepare and commit. The staged `target` therefore
    ///   fixes the live version at prepare time; if it is not `expected + 1` we
    ///   abort the (nothing-staged-yet) saga and fail closed.
    pub async fn rotate_at_version(
        &self,
        owner: OwnerAuthority,
        record_id: SealedRecordId,
        literal: SealedLiteral,
        now_ms: i64,
        expected_version: u32,
    ) -> Result<SealedValueSummary> {
        let row = self
            .db
            .sealed_value_record(record_id.to_string())
            .await?
            .context("sealed value record does not exist")?;
        if row.scope == SealedScopeKind::KnowledgeBase {
            bail!("knowledge-base sealed values do not support owner action rotation");
        }
        if row.scope == SealedScopeKind::Session {
            let literal_str = literal.expose_for_redaction().to_string();
            let resolver = self.redaction_resolver.as_ref().context(
                "session-scoped sealed rotate requires an installed redaction-history resolver to \
                 journal the adoption (decision 10.1); refusing to persist a rotated sealed \
                 literal unjournaled",
            )?;
            let session_id = row.scope_key.clone();
            // Predict the journaled version from the CAPABILITY's bound version,
            // not a pre-transaction read; the transaction re-validates it
            // authoritatively below.
            let new_version = i64::from(expected_version) + 1;
            let protected = ProtectedLiteral::new(
                literal_str.clone(),
                RedactionHistorySource::Sealed,
                Some(record_id.to_string()),
                Some(new_version),
            )?;
            let history = ProtectedRedactionHistory::new(&self.db, resolver.as_ref());
            let prepared = history.prepare_append(&session_id, protected).await?;

            let record_id_str = record_id.to_string();
            let vault = self.compartment.vault().cloned().ok_or_else(|| {
                anyhow::anyhow!("session sealed rotate requires a vault-backed compartment")
            })?;
            let session_key = row.scope_key.clone();
            let name = row.name.clone();
            let rotated = self
                .db
                .transaction(move |conn| {
                    let rotated = rotate_session_sealed_value_conn(
                        conn,
                        &record_id_str,
                        &literal_str,
                        now_ms,
                    )?;
                    // Atomic version fence: the committed version must be exactly
                    // one past the bound version, i.e. we rotated *from*
                    // `expected_version`. If a concurrent rotation moved the row
                    // first, the committed version is higher and the whole
                    // rotation (bump + grant revocation + journal) rolls back.
                    if rotated.active_version != new_version {
                        bail!(
                            "version mismatch: capability bound to version {expected_version} but \
                             the live record is at version {}",
                            rotated.active_version.saturating_sub(1)
                        );
                    }
                    let item_id = crate::secure_key::session_sealed_item_id(
                        &session_key,
                        &name,
                        rotated.active_version,
                    );
                    vault
                        .put_item_on_conn(
                            conn,
                            SecretVaultKind::SessionSealedValue,
                            &item_id,
                            literal_str.as_bytes(),
                        )
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    append_and_attach_conn(conn, &prepared, &[])?;
                    Ok(rotated)
                })
                .await?;
            return SealedValueSummary::from_row(&rotated);
        }

        // Compartment scope. `prepare_rotate` fixes the live version under the
        // saga-in-flight lock; nothing is staged yet, so a mismatch aborts by
        // simply removing the saga row.
        let ticket = self.prepare_rotate(owner, record_id, now_ms).await?;
        if ticket.target_version.checked_sub(1) != Some(expected_version) {
            let live = ticket.target_version.saturating_sub(1);
            self.finish_saga(owner, &ticket).await?;
            bail!(
                "version mismatch: capability bound to version {expected_version} but the live \
                 record is at version {live}"
            );
        }
        self.stage_literal(&ticket, literal)?;
        let summary = self.commit_rotate(owner, &ticket, now_ms).await?;
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

    /// Promote a session-scoped sealed value into Project or Global scope.
    ///
    /// The Owner capability binds the source version. The current session
    /// literal is copied to a fresh opaque compartment locator and the record
    /// is moved in the same SQLite transaction that removes its session vault
    /// generations, legacy metadata, and stale action grants. A promoted value
    /// therefore cannot be reclaimed by the session-end purge.
    pub async fn promote_session_at_version(
        &self,
        _owner: OwnerAuthority,
        record_id: SealedRecordId,
        target_scope: SealedScopeRef,
        now_ms: i64,
        expected_version: u32,
    ) -> Result<SealedValueSummary> {
        if !target_scope.kind().is_persistent_compartment() {
            bail!("session sealed values may only be promoted to project or global scope");
        }
        let row = self
            .db
            .sealed_value_record(record_id.to_string())
            .await?
            .context("sealed value record does not exist")?;
        if row.scope != SealedScopeKind::Session
            || !row.is_resolvable()
            || row.active_version != i64::from(expected_version)
        {
            bail!("sealed value changed before promotion");
        }
        let vault = self
            .compartment
            .vault()
            .cloned()
            .context("session sealed value promotion requires a vault-backed compartment")?;
        let source_item_id = crate::secure_key::session_sealed_item_id(
            &row.scope_key,
            &row.name,
            row.active_version,
        );
        let literal = vault
            .get_item(SecretVaultKind::SessionSealedValue, &source_item_id)
            .map_err(|error| {
                anyhow::anyhow!("reading session sealed value for promotion: {error}")
            })?;
        let target_key = SealedCompartmentKey::generate();
        let record_id_str = record_id.to_string();
        let target_scope_kind = target_scope.kind();
        let target_scope_key = target_scope.scope_key();
        let promoted = self
            .db
            .transaction(move |conn| {
                vault
                    .put_item_on_conn(
                        conn,
                        SecretVaultKind::SealedCompartment,
                        target_key.as_str(),
                        literal.as_slice(),
                    )
                    .map_err(|error| anyhow::anyhow!("staging promoted sealed literal: {error}"))?;
                promote_session_sealed_value_conn(
                    conn,
                    &record_id_str,
                    i64::from(expected_version),
                    target_scope_kind,
                    &target_scope_key,
                    target_key.as_str(),
                    now_ms,
                )
            })
            .await?;
        SealedValueSummary::from_row(&promoted)
    }

    /// Explicitly reset a session-scoped value. The version check is fused with
    /// the deletion so a stale owner capability cannot erase a later rotation.
    pub async fn reset_session_at_version(
        &self,
        _owner: OwnerAuthority,
        record_id: SealedRecordId,
        now_ms: i64,
        expected_version: u32,
    ) -> Result<bool> {
        self.db
            .delete_session_sealed_value_at_version(
                record_id.to_string(),
                i64::from(expected_version),
                now_ms,
            )
            .await
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
        if row.scope == SealedScopeKind::KnowledgeBase {
            bail!(
                "knowledge-base sealed values are not managed by the owner action-grant directory"
            );
        }
        if row.scope == SealedScopeKind::Session {
            let deleted = self
                .db
                .delete_session_sealed_value(record_id.to_string(), now_ms)
                .await?;
            if deleted && let Some(vault) = self.compartment.vault() {
                let max_version = row.active_version.max(1);
                for version in 1..=max_version {
                    let item_id = crate::secure_key::session_sealed_item_id(
                        &row.scope_key,
                        &row.name,
                        version,
                    );
                    match vault.delete_item(
                        cockpit_db::secret_vault::SecretVaultKind::SessionSealedValue,
                        &item_id,
                    ) {
                        Ok(()) | Err(crate::secure_key::SecureKeyError::NotFound(_)) => {}
                        Err(error) => {
                            return Err(anyhow::anyhow!(
                                "deleting session sealed vault item: {error}"
                            ));
                        }
                    }
                }
            }
            return Ok(deleted);
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
