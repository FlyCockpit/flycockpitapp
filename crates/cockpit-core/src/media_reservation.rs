//! Durable, checked media-resource accounting driven exclusively by evaluated policy plans.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Result, anyhow, bail};
use cockpit_config::config::media_budget::{
    MediaAccumulation, MediaAggregationScope, MediaCharge, MediaDimension, MediaReservationPlan,
};
use cockpit_db::Db;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

fn sqlite_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| anyhow!("sqlite integer overflow"))
}

fn sqlite_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn row_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    sqlite_u64(row.get::<_, i64>(index)?)
}

fn lowercase_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

pub trait MonotonicClock: Send + Sync {
    fn now_ms(&self) -> u64;
}
pub trait LocalExpiryCleanup: Send + Sync {
    fn kill_reap_and_cleanup(&self, reservation_id: &str) -> Result<String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaOwner {
    pub project_id: String,
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct ReserveRequest {
    pub reservation_id: String,
    pub recovery_id: String,
    pub owner: MediaOwner,
    pub operation: String,
    pub purpose: String,
    pub plans: Vec<MediaReservationPlan>,
    pub wall_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    ReservedQueued,
    ExecutingLocal,
    DispatchingExternal,
    ExternalPending,
    ReconcilingExternal,
    CancellationRequested,
    OverageQuarantined,
    Settling,
    Released,
    AccountingCorrupt,
}

impl ReservationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReservedQueued => "reserved_queued",
            Self::ExecutingLocal => "executing_local",
            Self::DispatchingExternal => "dispatching_external",
            Self::ExternalPending => "external_pending",
            Self::ReconcilingExternal => "reconciling_external",
            Self::CancellationRequested => "cancellation_requested",
            Self::OverageQuarantined => "overage_quarantined",
            Self::Settling => "settling",
            Self::Released => "released",
            Self::AccountingCorrupt => "accounting_corrupt",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "reserved_queued" => Self::ReservedQueued,
            "executing_local" => Self::ExecutingLocal,
            "dispatching_external" => Self::DispatchingExternal,
            "external_pending" => Self::ExternalPending,
            "reconciling_external" => Self::ReconcilingExternal,
            "cancellation_requested" => Self::CancellationRequested,
            "overage_quarantined" => Self::OverageQuarantined,
            "settling" => Self::Settling,
            "released" => Self::Released,
            "accounting_corrupt" => Self::AccountingCorrupt,
            _ => bail!("unknown media reservation state"),
        })
    }

    pub const fn allows(self, next: Self) -> bool {
        use ReservationState as S;
        matches!(
            (self, next),
            (
                S::ReservedQueued,
                S::ExecutingLocal | S::DispatchingExternal | S::CancellationRequested | S::Settling
            ) | (
                S::ExecutingLocal,
                S::DispatchingExternal
                    | S::CancellationRequested
                    | S::Settling
                    | S::OverageQuarantined
                    | S::AccountingCorrupt
            ) | (
                S::DispatchingExternal,
                S::ExternalPending
                    | S::CancellationRequested
                    | S::Settling
                    | S::OverageQuarantined
                    | S::AccountingCorrupt
            ) | (
                S::ExternalPending,
                S::ReconcilingExternal
                    | S::CancellationRequested
                    | S::Settling
                    | S::OverageQuarantined
                    | S::AccountingCorrupt
            ) | (
                S::ReconcilingExternal,
                S::ExternalPending
                    | S::CancellationRequested
                    | S::Settling
                    | S::OverageQuarantined
                    | S::AccountingCorrupt
            ) | (
                S::CancellationRequested,
                S::ExternalPending
                    | S::ReconcilingExternal
                    | S::Settling
                    | S::OverageQuarantined
                    | S::AccountingCorrupt
            ) | (S::OverageQuarantined, S::Settling | S::AccountingCorrupt)
                | (
                    S::Settling,
                    S::Released | S::OverageQuarantined | S::AccountingCorrupt
                )
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReservationReceipt {
    pub reservation_id: String,
    pub state: ReservationState,
    pub version: u64,
    pub queue_sequence: u64,
    pub deadline_monotonic_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MediaDenial {
    pub code: &'static str,
    pub dimension: String,
    pub requested: u64,
    pub effective: u64,
    pub current: u64,
    pub scope: String,
    pub source: String,
    pub retryable: bool,
}

#[derive(Debug, Clone)]
pub struct AccountingRepairRequest {
    pub attempt_id: String,
    pub scope_kind: String,
    pub scope_id: String,
    pub expected_block_generation: u64,
    pub repair_plan_digest: String,
    pub idempotency_key: String,
    pub wall_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountingRepairOutcome {
    Committed,
    Conflict,
    NotProvable,
    SourceChanged,
    Overflow,
    Unauthorized,
}

impl AccountingRepairOutcome {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Committed => "accounting_repair_committed",
            Self::Conflict => "accounting_repair_conflict",
            Self::NotProvable => "accounting_repair_not_provable",
            Self::SourceChanged => "accounting_repair_source_changed",
            Self::Overflow => "accounting_repair_overflow",
            Self::Unauthorized => "accounting_repair_unauthorized",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("media resource denied")]
    Denied(MediaDenial),
    #[error("media accounting is blocked")]
    AccountingBlocked,
    #[error("stale reservation version")]
    StaleVersion,
    #[error("invalid reservation transition")]
    InvalidTransition,
    #[error("media accounting overflow")]
    Overflow,
    #[error(transparent)]
    Storage(#[from] anyhow::Error),
}

#[derive(Clone)]
pub struct MediaReservationLedger {
    db: Db,
    clock: Arc<dyn MonotonicClock>,
}

impl MediaReservationLedger {
    pub fn new(db: Db, clock: Arc<dyn MonotonicClock>) -> Self {
        Self { db, clock }
    }

    pub async fn reserve(
        &self,
        request: ReserveRequest,
    ) -> Result<ReservationReceipt, LedgerError> {
        validate_plans(&request.plans)?;
        let now = self.clock.now_ms();
        let deadline = request
            .plans
            .iter()
            .find(|plan| plan.dimension == MediaDimension::OperationDeadlineSeconds)
            .ok_or_else(|| anyhow!("evaluated plan omitted operation deadline"))?
            .requested
            .checked_mul(1_000)
            .and_then(|duration| now.checked_add(duration))
            .ok_or(LedgerError::Overflow)?;
        let session = request.owner.session_id.clone();
        let receipt = self.db.transaction(move |conn| {
            if let Some((recovery,state,version,sequence,stored_deadline))=conn.query_row("SELECT recovery_id,state,version,queue_sequence,deadline_monotonic_ms FROM media_reservations WHERE reservation_id=?1",[&request.reservation_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,row_u64(r,2)?,row_u64(r,3)?,row_u64(r,4)?))).optional()? {
                if recovery!=request.recovery_id{return Err(anyhow!("idempotency_conflict"));}
                return Ok(ReservationReceipt{reservation_id:request.reservation_id,state:ReservationState::parse(&state)?,version,queue_sequence:sequence,deadline_monotonic_ms:stored_deadline});
            }
            for (kind, id) in [("global", "global"), ("project", request.owner.project_id.as_str()), ("session", request.owner.session_id.as_str())] {
                if conn.query_row("SELECT 1 FROM media_accounting_blocks WHERE scope_kind=?1 AND scope_id=?2", params![kind,id], |_| Ok(())).optional()?.is_some() {
                    return Err(anyhow!("accounting_blocked"));
                }
            }
            let queue_sequence = conn.query_row("UPDATE media_queue_sequence SET next_value=next_value+1 WHERE singleton=1 RETURNING next_value-1", [], |row| row_u64(row, 0))?;
            let policy_version = request.plans[0].policy_version;
            conn.execute(
                "INSERT INTO media_reservations(reservation_id,policy_version,project_id,owner_session_key,operation,purpose,recovery_id,state,version,queue_sequence,deadline_monotonic_ms,created_wall_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,'reserved_queued',1,?8,?9,?10)",
                params![request.reservation_id, sqlite_i64(policy_version)?, request.owner.project_id, request.owner.session_id, request.operation, request.purpose, request.recovery_id, sqlite_i64(queue_sequence)?, sqlite_i64(deadline)?, sqlite_i64(request.wall_ms)?],
            )?;
            for plan in request.plans.iter().filter(|plan| reserves_at_enqueue(plan)) {
                acquire(conn, &request, plan, 1, request.wall_ms)?;
            }
            for plan in request.plans.iter().filter(|plan| matches!(plan.scope_policy.charge,MediaCharge::AcquireAtPromotion|MediaCharge::AcceptedOrPossiblyAccepted|MediaCharge::AtHandoff)) { record_deferred_estimate(conn,&request,plan,request.wall_ms)?; }
            Ok(ReservationReceipt { reservation_id: request.reservation_id, state: ReservationState::ReservedQueued, version: 1, queue_sequence, deadline_monotonic_ms: deadline })
        }).await.map_err(classify_storage_error)?;
        let _ = session;
        Ok(receipt)
    }

    pub async fn transition(
        &self,
        id: &str,
        expected_version: u64,
        next: ReservationState,
        wall_ms: u64,
    ) -> Result<ReservationReceipt, LedgerError> {
        let id = id.to_owned();
        self.db.transaction(move |conn| {
            let row = conn.query_row("SELECT state,version,queue_sequence,deadline_monotonic_ms,project_id,owner_session_key,external_operation_id FROM media_reservations WHERE reservation_id=?1", [&id], |row| Ok((row.get::<_,String>(0)?,row_u64(row,1)?,row_u64(row,2)?,row_u64(row,3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?,row.get::<_,Option<String>>(6)?)))?;
            let current = ReservationState::parse(&row.0)?;
            if row.1 != expected_version { return Err(anyhow!("stale_version")); }
            if !current.allows(next) { return Err(anyhow!("invalid_transition")); }
            if next==ReservationState::Released{return Err(anyhow!("verified_settlement_required"));}
            if next == ReservationState::DispatchingExternal && row.6.is_none() { return Err(anyhow!("external_journal_required")); }
            let version = expected_version.checked_add(1).ok_or_else(|| anyhow!("accounting_overflow"))?;
            conn.execute("UPDATE media_reservations SET state=?1,version=?2 WHERE reservation_id=?3 AND version=?4", params![next.as_str(),sqlite_i64(version)?,id,sqlite_i64(expected_version)?])?;
            conn.execute("INSERT INTO media_reservation_deltas(reservation_id,reservation_version,dimension,scope_kind,scope_id,estimated,delta,charged_after,fact_kind,created_wall_ms) VALUES(?1,?2,'state_transition','operation',?1,0,0,0,'actual',?3)", params![id,sqlite_i64(version)?,sqlite_i64(wall_ms)?])?;
            if next == ReservationState::AccountingCorrupt { conn.execute("INSERT INTO media_accounting_blocks(scope_kind,scope_id,generation,reason) VALUES('session',?1,1,'accounting_corrupt') ON CONFLICT(scope_kind,scope_id) DO UPDATE SET generation=generation+1,reason='accounting_corrupt'",[row.5.as_str()])?; }
            Ok(ReservationReceipt { reservation_id:id,state:next,version,queue_sequence:row.2,deadline_monotonic_ms:row.3 })
        }).await.map_err(classify_storage_error)
    }

    pub async fn handoff_external(
        &self,
        id: &str,
        expected_version: u64,
        journal_operation_id: &str,
        handoff_plans: Vec<MediaReservationPlan>,
        wall_ms: u64,
    ) -> Result<ReservationReceipt, LedgerError> {
        let id = id.to_owned();
        let journal = journal_operation_id.to_owned();
        let now = self.clock.now_ms();
        self.db.transaction(move |conn| {
            let(state,version,sequence,deadline,project,session)=conn.query_row("SELECT state,version,queue_sequence,deadline_monotonic_ms,project_id,owner_session_key FROM media_reservations WHERE reservation_id=?1",[&id],|r|Ok((r.get::<_,String>(0)?,row_u64(r,1)?,row_u64(r,2)?,row_u64(r,3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?)))?;
            ensure_unblocked(conn,&session)?;if now>=deadline{return Err(anyhow!("deadline_expired"));}if version!=expected_version{return Err(anyhow!("stale_version"));}
            if !ReservationState::parse(&state)?.allows(ReservationState::DispatchingExternal){return Err(anyhow!("invalid_transition"));}
            let(journal_owner,journal_state):(String,String)=conn.query_row("SELECT owner_session_id,state FROM external_journal_operations WHERE operation_id=?1",[&journal],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?.ok_or_else(||anyhow!("external_journal_required"))?;
            if journal_owner!=session{return Err(anyhow!("external_journal_owner_mismatch"));}if journal_state!="prepared"{return Err(anyhow!("external_journal_not_prepared"));}
            let owner=MediaOwner{project_id:project,session_id:session};release_queued(conn,&id,&owner,version+1,wall_ms)?;
            for plan in &handoff_plans{if !matches!(plan.scope_policy.charge,MediaCharge::AcceptedOrPossiblyAccepted|MediaCharge::AtHandoff){return Err(anyhow!("invalid_handoff_plan"));}acquire_plan(conn,&id,&owner,plan,version+1,wall_ms)?;}
            conn.execute("UPDATE media_reservations SET external_operation_id=?1,state='dispatching_external',version=version+1 WHERE reservation_id=?2 AND version=?3",params![journal,id,sqlite_i64(expected_version)?])?;
            Ok(ReservationReceipt{reservation_id:id,state:ReservationState::DispatchingExternal,version:version+1,queue_sequence:sequence,deadline_monotonic_ms:deadline})
        }).await.map_err(classify_storage_error)
    }

    pub async fn promote(
        &self,
        id: &str,
        expected_version: u64,
        execution_plan: MediaReservationPlan,
        wall_ms: u64,
    ) -> Result<ReservationReceipt, LedgerError> {
        if execution_plan.scope_policy.charge != MediaCharge::AcquireAtPromotion {
            return Err(LedgerError::InvalidTransition);
        }
        let id = id.to_owned();
        let now = self.clock.now_ms();
        self.db.transaction(move |conn| {
            let (state, version, deadline, project, session, sequence) = conn.query_row("SELECT state,version,deadline_monotonic_ms,project_id,owner_session_key,queue_sequence FROM media_reservations WHERE reservation_id=?1", [&id], |r| Ok((r.get::<_,String>(0)?,row_u64(r,1)?,row_u64(r,2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,row_u64(r,5)?)))?;
            if version != expected_version { return Err(anyhow!("stale_version")); }
            if ReservationState::parse(&state)? != ReservationState::ReservedQueued { return Err(anyhow!("invalid_transition")); }
            if now >= deadline { return Err(anyhow!("deadline_expired")); }
            let owner = MediaOwner { project_id: project, session_id: session }; ensure_unblocked(conn, &owner.session_id)?;
            validate_mutation_policy(conn,&id,&execution_plan)?;
            acquire_plan(conn, &id, &owner, &execution_plan, version + 1, wall_ms)?;
            release_queued(conn, &id, &owner, version + 1, wall_ms)?;
            conn.execute("UPDATE media_reservations SET state='executing_local',version=version+1 WHERE reservation_id=?1 AND version=?2", params![id,sqlite_i64(expected_version)?])?;
            Ok(ReservationReceipt { reservation_id:id,state:ReservationState::ExecutingLocal,version:version+1,queue_sequence:sequence,deadline_monotonic_ms:deadline })
        }).await.map_err(classify_storage_error)
    }

    pub async fn expire_before_handoff(
        &self,
        id: &str,
        expected_version: u64,
        wall_ms: u64,
        cleanup: &dyn LocalExpiryCleanup,
    ) -> Result<ReservationReceipt, LedgerError> {
        let id = id.to_owned();
        let now = self.clock.now_ms();
        let cancellation_id = id.clone();
        let cancelled=self.db.transaction(move|conn|{let(state,version,sequence,deadline)=conn.query_row("SELECT state,version,queue_sequence,deadline_monotonic_ms FROM media_reservations WHERE reservation_id=?1",[&cancellation_id],|r|Ok((r.get::<_,String>(0)?,row_u64(r,1)?,row_u64(r,2)?,row_u64(r,3)?)))?;if version!=expected_version{return Err(anyhow!("stale_version"));}if now<deadline{return Err(anyhow!("invalid_transition"));}let current=ReservationState::parse(&state)?;if !matches!(current,ReservationState::ReservedQueued|ReservationState::ExecutingLocal){return Err(anyhow!("invalid_transition"));}let next_version=version.checked_add(1).ok_or_else(||anyhow!("accounting_overflow"))?;conn.execute("UPDATE media_reservations SET state='cancellation_requested',version=?1 WHERE reservation_id=?2",params![sqlite_i64(next_version)?,cancellation_id])?;Ok(ReservationReceipt{reservation_id:cancellation_id,state:ReservationState::CancellationRequested,version:next_version,queue_sequence:sequence,deadline_monotonic_ms:deadline})}).await.map_err(classify_storage_error)?;
        let cleanup_checksum = cleanup
            .kill_reap_and_cleanup(&id)
            .map_err(LedgerError::Storage)?;
        if cleanup_checksum.is_empty() {
            return Err(LedgerError::Storage(anyhow!(
                "cleanup attestation checksum required"
            )));
        }
        self.db.transaction(move|conn|{let version=cancelled.version;let sequence=cancelled.queue_sequence;let deadline=cancelled.deadline_monotonic_ms;for dimension in [MediaDimension::EncodedBytesPerObject,MediaDimension::RetainedBytesPerSession]{conn.execute("INSERT OR IGNORE INTO media_cleanup_attestations(reservation_id,dimension,attestation_kind,checksum,created_wall_ms) VALUES(?1,?2,'zero_materialized_or_verified_cleaned',?3,?4)",params![id,dimension_name(dimension),cleanup_checksum,wall_ms])?;}let state:String=conn.query_row("SELECT state FROM media_reservations WHERE reservation_id=?1 AND version=?2",params![id,version],|r|r.get(0))?;if ReservationState::parse(&state)?!=ReservationState::CancellationRequested{return Err(anyhow!("stale_version"));}let settling_version=version+1;conn.execute("UPDATE media_reservations SET state='settling',version=?1 WHERE reservation_id=?2",params![settling_version,id])?;release_restart_dimensions(conn,&id,settling_version,wall_ms)?;let next=if has_releasable_balance(conn,&id)?{ReservationState::Settling}else{ReservationState::Released};let final_version=if next==ReservationState::Released{settling_version+1}else{settling_version};if next==ReservationState::Released{conn.execute("UPDATE media_reservations SET state='released',version=?1 WHERE reservation_id=?2",params![final_version,id])?;}Ok(ReservationReceipt{reservation_id:id,state:next,version:final_version,queue_sequence:sequence,deadline_monotonic_ms:deadline})}).await.map_err(classify_storage_error)
    }

    pub async fn reconcile_actual(
        &self,
        id: &str,
        expected_version: u64,
        dimension: MediaDimension,
        actual: u64,
        verified_cleanup: bool,
        wall_ms: u64,
    ) -> Result<ReservationReceipt, LedgerError> {
        if !dimension.scope_policy().reconcile_actual {
            return Err(LedgerError::InvalidTransition);
        }
        let id = id.to_owned();
        let dimension_name = dimension_name(dimension);
        self.db.transaction(move |conn| {
            let (state,version,project,session,sequence,deadline)=conn.query_row("SELECT state,version,project_id,owner_session_key,queue_sequence,deadline_monotonic_ms FROM media_reservations WHERE reservation_id=?1",[&id],|r|Ok((r.get::<_,String>(0)?,row_u64(r,1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,row_u64(r,4)?,row_u64(r,5)?)))?;
            if version != expected_version { return Err(anyhow!("stale_version")); }
            let estimated=conn.query_row("SELECT COALESCE(MAX(estimated),0) FROM media_reservation_deltas WHERE reservation_id=?1 AND dimension=?2",params![id,dimension_name],|r|row_u64(r,0))?;
            let owner=MediaOwner{project_id:project,session_id:session} ;
            let (scope_kind,scope_id)=scope_identity(dimension.scope_policy().scope,&owner,&id);
            let next_version=version.checked_add(1).ok_or_else(||anyhow!("accounting_overflow"))?;
            let mut next=ReservationState::parse(&state)?;
            if matches!(next,ReservationState::Released|ReservationState::AccountingCorrupt){return Err(anyhow!("invalid_transition"));}
            if actual > estimated {
                if !next.allows(ReservationState::OverageQuarantined){return Err(anyhow!("invalid_transition"));}
                let extra=actual.checked_sub(estimated).ok_or_else(||anyhow!("accounting_overflow"))?;
                mutate_counter(conn,scope_kind,&scope_id,&dimension_name,i64::try_from(extra)?)?;
                record_delta(conn,&id,next_version,&dimension_name,scope_kind,&scope_id,actual,i64::try_from(extra)?,"overage",wall_ms)?;
                next=ReservationState::OverageQuarantined;
                conn.execute("UPDATE media_reservations SET quarantined=1,published=0 WHERE reservation_id=?1",[&id])?;
            } else if verified_cleanup && dimension.scope_policy().release.is_reclaimable() {
                if !matches!(next,ReservationState::Settling|ReservationState::OverageQuarantined|ReservationState::CancellationRequested|ReservationState::ReconcilingExternal){return Err(anyhow!("invalid_transition"));}
                if matches!(dimension.scope_policy().release,cockpit_config::config::media_budget::MediaRelease::VerifiedDeletion|cockpit_config::config::media_budget::MediaRelease::BytesDestroyed)&&!deletion_is_proven(conn,&id,&dimension_name)?{return Err(anyhow!("verified_deletion_required"));}
                let outstanding:i64=conn.query_row("SELECT COALESCE(SUM(delta),0) FROM media_reservation_deltas WHERE reservation_id=?1 AND dimension=?2",params![id,dimension_name],|r|r.get(0))?;
                let target=i64::try_from(actual)?;
                let release=outstanding.checked_sub(target).ok_or_else(||anyhow!("accounting_overflow"))?.max(0);
                if release>0{mutate_counter(conn,scope_kind,&scope_id,&dimension_name,-release)?;record_delta(conn,&id,next_version,&dimension_name,scope_kind,&scope_id,actual,-release,"cleanup",wall_ms)?;}
            }
            conn.execute("UPDATE media_reservations SET state=?1,version=?2 WHERE reservation_id=?3",params![next.as_str(),sqlite_i64(next_version)?,id])?;
            Ok(ReservationReceipt{reservation_id:id,state:next,version:next_version,queue_sequence:sequence,deadline_monotonic_ms:deadline})
        }).await.map_err(classify_storage_error)
    }

    pub async fn recover_after_restart(&self, wall_ms: u64) -> Result<u64, LedgerError> {
        self.db.transaction(move |conn| {
            let mut stmt=conn.prepare("SELECT reservation_id,version,state FROM media_reservations WHERE state IN ('reserved_queued','executing_local','settling') OR (state='cancellation_requested' AND external_operation_id IS NULL)")?;
            let rows=stmt.query_map([],|r|Ok((r.get::<_,String>(0)?,row_u64(r,1)?,r.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            drop(stmt);
            for (id,version,_) in &rows {
                release_restart_dimensions(conn,id,version+1,wall_ms)?;
                let next_version=version.checked_add(1).ok_or_else(||anyhow!("accounting_overflow"))?;
                conn.execute("UPDATE media_reservations SET state='settling',version=?1 WHERE reservation_id=?2",params![sqlite_i64(next_version)?,id])?;
                conn.execute("INSERT INTO media_reservation_deltas(reservation_id,reservation_version,dimension,scope_kind,scope_id,estimated,delta,charged_after,fact_kind,created_wall_ms) VALUES(?1,?2,'restart_expiry','operation',?1,0,0,0,'cleanup',?3)",params![id,sqlite_i64(next_version)?,sqlite_i64(wall_ms)?])?;
            }
            Ok(rows.len() as u64)
        }).await.map_err(classify_storage_error)
    }

    /// Releases only dimensions whose cleanup/reconciliation has been
    /// independently verified. Durable (`Never`) charges are never accepted.
    pub async fn settle_verified(
        &self,
        id: &str,
        expected_version: u64,
        verified_dimensions: Vec<MediaDimension>,
        wall_ms: u64,
    ) -> Result<ReservationReceipt, LedgerError> {
        let id = id.to_owned();
        self.db.transaction(move |conn| {
            let (state,version,sequence,deadline)=conn.query_row("SELECT state,version,queue_sequence,deadline_monotonic_ms FROM media_reservations WHERE reservation_id=?1",[&id],|r|Ok((r.get::<_,String>(0)?,row_u64(r,1)?,row_u64(r,2)?,row_u64(r,3)?)))?;
            if version!=expected_version{return Err(anyhow!("stale_version"));}
            let current=ReservationState::parse(&state)?;
            if current!=ReservationState::Settling&&!current.allows(ReservationState::Settling){return Err(anyhow!("invalid_transition"));}
            let settling_version=version.checked_add(1).ok_or_else(||anyhow!("accounting_overflow"))?;
            if current!=ReservationState::Settling{conn.execute("UPDATE media_reservations SET state='settling',version=?1 WHERE reservation_id=?2",params![sqlite_i64(settling_version)?,id])?;}
            let next_version=if current==ReservationState::Settling{settling_version}else{settling_version.checked_add(1).ok_or_else(||anyhow!("accounting_overflow"))?};
            for dimension in verified_dimensions {
                if dimension.scope_policy().release==cockpit_config::config::media_budget::MediaRelease::Never{return Err(anyhow!("durable_charge_not_releasable"));}
                if dimension==MediaDimension::OutboundSubmissionsGlobal&&!external_reconciliation_is_terminal(conn,&id)?{return Err(anyhow!("external_reconciliation_required"));}
                if matches!(dimension.scope_policy().release,cockpit_config::config::media_budget::MediaRelease::VerifiedDeletion|cockpit_config::config::media_budget::MediaRelease::BytesDestroyed)&&!deletion_is_proven(conn,&id,&dimension_name(dimension))?{return Err(anyhow!("verified_deletion_required"));}
                release_dimension_balance(conn,&id,next_version,&dimension_name(dimension),wall_ms)?;
            }
            let next=if has_releasable_balance(conn,&id)?{ReservationState::Settling}else{ReservationState::Released};
            conn.execute("UPDATE media_reservations SET state=?1,version=?2 WHERE reservation_id=?3",params![next.as_str(),sqlite_i64(next_version)?,id])?;
            Ok(ReservationReceipt{reservation_id:id,state:next,version:next_version,queue_sequence:sequence,deadline_monotonic_ms:deadline})
        }).await.map_err(classify_storage_error)
    }

    pub async fn diagnose_accounting(
        &self,
        scope_kind: &str,
        scope_id: &str,
    ) -> Result<AccountingDiagnosis, LedgerError> {
        validate_repair_scope(scope_kind)?;
        let kind = scope_kind.to_owned();
        let id = scope_id.to_owned();
        self.db
            .read(move |conn| diagnose_connection(conn, &kind, &id))
            .await
            .map_err(LedgerError::Storage)
    }

    pub async fn record_artifact_manifest(
        &self,
        reservation_id: &str,
        artifact_id: &str,
        dimension: MediaDimension,
        byte_count: u64,
        checksum: &str,
        quarantined: bool,
    ) -> Result<(), LedgerError> {
        let reservation = reservation_id.to_owned();
        let artifact = artifact_id.to_owned();
        let checksum = checksum.to_owned();
        if checksum.is_empty() {
            return Err(LedgerError::Storage(anyhow!("artifact checksum required")));
        }
        let dimension = dimension_name(dimension);
        self.db.transaction(move|conn|{conn.execute("INSERT INTO media_artifact_facts(artifact_id,reservation_id,dimension,byte_count,checksum,quarantined) VALUES(?1,?2,?3,?4,?5,?6)",params![artifact,reservation,dimension,sqlite_i64(byte_count)?,checksum,quarantined])?;Ok(())}).await.map_err(LedgerError::Storage)
    }

    pub async fn record_verified_deletion(
        &self,
        artifact_id: &str,
        expected_checksum: &str,
        tombstone_checksum: &str,
    ) -> Result<(), LedgerError> {
        let artifact = artifact_id.to_owned();
        let expected = expected_checksum.to_owned();
        let tombstone = tombstone_checksum.to_owned();
        if tombstone.is_empty() {
            return Err(LedgerError::Storage(anyhow!("deletion tombstone required")));
        }
        self.db.transaction(move|conn|{let (stored,prior):(String,Option<String>)=conn.query_row("SELECT checksum,deletion_tombstone_checksum FROM media_artifact_facts WHERE artifact_id=?1",[&artifact],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?)))?;if stored!=expected{return Err(anyhow!("artifact checksum mismatch"));}if let Some(prior)=prior{if prior==tombstone{return Ok(());}return Err(anyhow!("deletion tombstone conflict"));}conn.execute("UPDATE media_artifact_facts SET deletion_tombstone_checksum=?1 WHERE artifact_id=?2 AND deletion_tombstone_checksum IS NULL",params![tombstone,artifact])?;Ok(())}).await.map_err(LedgerError::Storage)
    }

    pub async fn publication_allowed(&self, reservation_id: &str) -> Result<bool, LedgerError> {
        let id = reservation_id.to_owned();
        self.db.read(move|conn|Ok(conn.query_row("SELECT published=1 AND quarantined=0 AND state NOT IN ('overage_quarantined','accounting_corrupt') FROM media_reservations WHERE reservation_id=?1",[id],|r|r.get(0))?)).await.map_err(LedgerError::Storage)
    }

    pub async fn authorize_publication(&self, reservation_id: &str) -> Result<(), LedgerError> {
        let id = reservation_id.to_owned();
        self.db.transaction(move|conn|{let changed=conn.execute("UPDATE media_reservations SET published=1 WHERE reservation_id=?1 AND quarantined=0 AND state NOT IN ('overage_quarantined','accounting_corrupt','cancellation_requested')",[id])?;if changed!=1{return Err(anyhow!("publication_denied"));}Ok(())}).await.map_err(LedgerError::Storage)
    }

    pub async fn repair_accounting(
        &self,
        request: AccountingRepairRequest,
        principal: &crate::daemon::principal::ClientPrincipal,
    ) -> Result<AccountingRepairOutcome, LedgerError> {
        if !principal.is_owner() {
            return Ok(AccountingRepairOutcome::Unauthorized);
        }
        validate_repair_scope(&request.scope_kind)?;
        self.db.transaction(move |conn| {
            let request_digest=repair_request_digest(&request);
            if let Some((stored,result))=conn.query_row("SELECT request_digest,outcome FROM media_repair_attempts WHERE idempotency_key=?1",[&request.idempotency_key],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Option<String>>(1)?))).optional()? {
                if stored!=request_digest{return Ok(AccountingRepairOutcome::Conflict);}
                return Ok(parse_repair_outcome(result.as_deref().unwrap_or("accounting_repair_not_provable")));
            }
            let diagnosis=diagnose_connection(conn,&request.scope_kind,&request.scope_id)?;
            conn.execute("INSERT INTO media_repair_attempts(attempt_id,scope_kind,scope_id,idempotency_key,request_digest,plan_digest,expected_block_generation,state,current_counter_digest,created_wall_ms,updated_wall_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,'planned',?8,?9,?9)",params![request.attempt_id,request.scope_kind,request.scope_id,request.idempotency_key,request_digest,request.repair_plan_digest,sqlite_i64(request.expected_block_generation)?,diagnosis.current_counter_digest,sqlite_i64(request.wall_ms)?])?;
            if request.scope_kind=="project"{return finish_repair(conn,&request.attempt_id,AccountingRepairOutcome::NotProvable,None,request.wall_ms);}
            if diagnosis.block_generation!=request.expected_block_generation||diagnosis.repair_plan_digest!=request.repair_plan_digest{return finish_repair(conn,&request.attempt_id,AccountingRepairOutcome::SourceChanged,None,request.wall_ms);}
            if diagnosis.journal_blockers>0||diagnosis.manifest_blockers>0{return finish_repair(conn,&request.attempt_id,AccountingRepairOutcome::NotProvable,None,request.wall_ms);}
            conn.execute("UPDATE media_repair_attempts SET state='rebuilding',updated_wall_ms=?2 WHERE attempt_id=?1",params![request.attempt_id,sqlite_i64(request.wall_ms)?])?;
            let rebuilt=match rebuild_counters(conn,&request.scope_kind,&request.scope_id){Ok(value)=>value,Err(error)=>{let outcome=if error.to_string().contains("overflow")||error.to_string().contains("out of range"){AccountingRepairOutcome::Overflow}else{AccountingRepairOutcome::NotProvable};return finish_repair(conn,&request.attempt_id,outcome,None,request.wall_ms);}};
            for(dimension,charged)in &rebuilt{conn.execute("INSERT INTO media_counter_shadow(attempt_id,dimension,charged) VALUES(?1,?2,?3)",params![request.attempt_id,dimension,sqlite_i64(*charged)?])?;}
            conn.execute("UPDATE media_repair_attempts SET state='verifying',updated_wall_ms=?2 WHERE attempt_id=?1",params![request.attempt_id,sqlite_i64(request.wall_ms)?])?;
            let verify=diagnose_connection(conn,&request.scope_kind,&request.scope_id)?;
            if verify.repair_plan_digest!=diagnosis.repair_plan_digest||verify.block_generation!=diagnosis.block_generation{return finish_repair(conn,&request.attempt_id,AccountingRepairOutcome::SourceChanged,None,request.wall_ms);}
            let prior_generation=conn.query_row("SELECT COALESCE(MAX(generation),0) FROM media_resource_counters WHERE scope_kind=?1 AND scope_id=?2",params![request.scope_kind,request.scope_id],|r|row_u64(r,0))?;
            let repaired_generation=prior_generation.max(diagnosis.block_generation).checked_add(1).ok_or_else(||anyhow!("accounting_repair_overflow"))?;
            conn.execute("DELETE FROM media_resource_counters WHERE scope_kind=?1 AND scope_id=?2",params![request.scope_kind,request.scope_id])?;
            for(dimension,charged)in &rebuilt{conn.execute("INSERT INTO media_resource_counters(scope_kind,scope_id,dimension,charged,generation) VALUES(?1,?2,?3,?4,?5)",params![request.scope_kind,request.scope_id,dimension,sqlite_i64(*charged)?,sqlite_i64(repaired_generation)?])?;}
            conn.execute("DELETE FROM media_accounting_blocks WHERE scope_kind=?1 AND scope_id=?2 AND generation=?3",params![request.scope_kind,request.scope_id,sqlite_i64(diagnosis.block_generation)?])?;
            finish_repair(conn,&request.attempt_id,AccountingRepairOutcome::Committed,Some(stable_counter_digest(&rebuilt)),request.wall_ms)
        }).await.map_err(|error| if error.to_string().contains("overflow"){LedgerError::Overflow}else{LedgerError::Storage(error)})
    }

    pub async fn next_fair_candidate(&self) -> Result<Option<String>, LedgerError> {
        self.db.transaction(|conn| {
            let last:Option<String>=conn.query_row("SELECT last_session_id FROM media_scheduler_cursor WHERE singleton=1",[],|r|r.get(0))?;
            let candidate:Option<(String,String)>=conn.query_row("WITH heads AS (SELECT owner_session_key,MIN(queue_sequence) sequence FROM media_reservations WHERE state='reserved_queued' GROUP BY owner_session_key) SELECT h.owner_session_key,r.reservation_id FROM heads h JOIN media_reservations r ON r.owner_session_key=h.owner_session_key AND r.queue_sequence=h.sequence ORDER BY CASE WHEN h.owner_session_key>?1 THEN 0 ELSE 1 END,h.owner_session_key LIMIT 1",[last.as_deref().unwrap_or("")],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?;
            if let Some((session,id))=candidate{conn.execute("UPDATE media_scheduler_cursor SET last_session_id=?1 WHERE singleton=1",[session])?;Ok(Some(id))}else{Ok(None)}
        }).await.map_err(LedgerError::Storage)
    }
}

fn validate_plans(plans: &[MediaReservationPlan]) -> Result<(), LedgerError> {
    if plans.is_empty() {
        return Err(LedgerError::Storage(anyhow!("empty evaluated plan")));
    }
    let version = plans[0].policy_version;
    let mut dimensions = BTreeSet::new();
    for plan in plans {
        if plan.policy_version != version
            || plan.requested == 0
            || plan.requested > plan.effective_limit
            || plan.scope_policy != plan.dimension.scope_policy()
            || !dimensions.insert(plan.dimension)
        {
            return Err(LedgerError::Storage(anyhow!("invalid evaluated plan set")));
        }
    }
    Ok(())
}
fn reserves_at_enqueue(plan: &MediaReservationPlan) -> bool {
    matches!(
        plan.scope_policy.charge,
        MediaCharge::ReserveAtEnqueue
            | MediaCharge::BeforeAllocation
            | MediaCharge::BeforeDecode
            | MediaCharge::WhileBytesExist
            | MediaCharge::WhileQueued
    )
}
fn dimension_name(d: MediaDimension) -> String {
    serde_json::to_value(d)
        .expect("media dimension serializes")
        .as_str()
        .expect("media dimension is a string")
        .to_owned()
}
fn scope_identity(
    scope: MediaAggregationScope,
    owner: &MediaOwner,
    reservation: &str,
) -> (&'static str, String) {
    match scope {
        MediaAggregationScope::Global => ("global", "global".into()),
        MediaAggregationScope::Session => ("session", owner.session_id.clone()),
        MediaAggregationScope::Operation => ("operation", reservation.into()),
        MediaAggregationScope::ImmutableRequest
        | MediaAggregationScope::RequestSum
        | MediaAggregationScope::RequestLocal => ("request", reservation.into()),
        MediaAggregationScope::Object | MediaAggregationScope::Derivative => {
            ("reservation", reservation.into())
        }
    }
}
fn ensure_unblocked(conn: &rusqlite::Connection, session_id: &str) -> Result<()> {
    if conn
        .query_row(
            "SELECT 1 FROM media_accounting_blocks WHERE scope_kind='session' AND scope_id=?1",
            [session_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        bail!("accounting_blocked");
    }
    Ok(())
}
fn validate_mutation_policy(
    conn: &rusqlite::Connection,
    id: &str,
    plan: &MediaReservationPlan,
) -> Result<()> {
    let version = conn.query_row(
        "SELECT policy_version FROM media_reservations WHERE reservation_id=?1",
        [id],
        |r| row_u64(r, 0),
    )?;
    if version != plan.policy_version {
        bail!("stale_policy_version");
    }
    Ok(())
}
fn acquire(
    conn: &rusqlite::Connection,
    request: &ReserveRequest,
    plan: &MediaReservationPlan,
    version: u64,
    wall_ms: u64,
) -> Result<()> {
    acquire_plan(
        conn,
        &request.reservation_id,
        &request.owner,
        plan,
        version,
        wall_ms,
    )
}
fn record_deferred_estimate(
    conn: &rusqlite::Connection,
    request: &ReserveRequest,
    plan: &MediaReservationPlan,
    wall_ms: u64,
) -> Result<()> {
    let name = dimension_name(plan.dimension);
    let (kind, scope_id) = scope_identity(
        plan.scope_policy.scope,
        &request.owner,
        &request.reservation_id,
    );
    record_delta(
        conn,
        &request.reservation_id,
        1,
        &name,
        kind,
        &scope_id,
        plan.requested,
        0,
        "reserve",
        wall_ms,
    )
}
fn acquire_plan(
    conn: &rusqlite::Connection,
    id: &str,
    owner: &MediaOwner,
    plan: &MediaReservationPlan,
    version: u64,
    wall_ms: u64,
) -> Result<()> {
    validate_mutation_policy(conn, id, plan)?;
    let reserved=conn.query_row("SELECT COALESCE(MAX(estimated),0) FROM media_reservation_deltas WHERE reservation_id=?1 AND dimension=?2",params![id,dimension_name(plan.dimension)],|r|row_u64(r,0))?;
    if reserved > 0 && plan.requested > reserved {
        bail!("immutable_estimate_exceeded");
    }
    let name = dimension_name(plan.dimension);
    let (kind, scope_id) = scope_identity(plan.scope_policy.scope, owner, id);
    let current=conn.query_row("SELECT charged FROM media_resource_counters WHERE scope_kind=?1 AND scope_id=?2 AND dimension=?3",params![kind,scope_id,name],|r|row_u64(r,0)).optional()?.unwrap_or(0);
    let next = current
        .checked_add(plan.requested)
        .ok_or_else(|| anyhow!("accounting_overflow"))?;
    if next > plan.effective_limit {
        bail!(
            "media_denied:{}:{}:{}:{}:{}:{:?}",
            name,
            plan.requested,
            plan.effective_limit,
            current,
            kind,
            plan.source
        );
    }
    mutate_counter(conn, kind, &scope_id, &name, i64::try_from(plan.requested)?)?;
    record_delta(
        conn,
        id,
        version,
        &name,
        kind,
        &scope_id,
        plan.requested,
        i64::try_from(plan.requested)?,
        "reserve",
        wall_ms,
    )
}
fn mutate_counter(
    conn: &rusqlite::Connection,
    kind: &str,
    id: &str,
    dimension: &str,
    delta: i64,
) -> Result<u64> {
    let current:i64=conn.query_row("SELECT charged FROM media_resource_counters WHERE scope_kind=?1 AND scope_id=?2 AND dimension=?3",params![kind,id,dimension],|r|r.get(0)).optional()?.unwrap_or(0);
    let next = current
        .checked_add(delta)
        .ok_or_else(|| anyhow!("accounting_overflow"))?;
    if next < 0 {
        bail!("accounting_corrupt_negative");
    }
    conn.execute("INSERT INTO media_resource_counters(scope_kind,scope_id,dimension,charged,generation) VALUES(?1,?2,?3,?4,1) ON CONFLICT(scope_kind,scope_id,dimension) DO UPDATE SET charged=excluded.charged,generation=generation+1",params![kind,id,dimension,next])?;
    Ok(u64::try_from(next)?)
}
#[allow(clippy::too_many_arguments)]
fn record_delta(
    conn: &rusqlite::Connection,
    reservation: &str,
    version: u64,
    dimension: &str,
    kind: &str,
    scope_id: &str,
    estimated: u64,
    delta: i64,
    fact: &str,
    wall_ms: u64,
) -> Result<()> {
    let charged=conn.query_row("SELECT charged FROM media_resource_counters WHERE scope_kind=?1 AND scope_id=?2 AND dimension=?3",params![kind,scope_id,dimension],|r|row_u64(r,0)).optional()?.unwrap_or(0);
    conn.execute("INSERT INTO media_reservation_deltas(reservation_id,reservation_version,dimension,scope_kind,scope_id,estimated,delta,charged_after,fact_kind,created_wall_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",params![reservation,sqlite_i64(version)?,dimension,kind,scope_id,sqlite_i64(estimated)?,delta,sqlite_i64(charged)?,fact,sqlite_i64(wall_ms)?])?;
    Ok(())
}
fn release_queued(
    conn: &rusqlite::Connection,
    id: &str,
    owner: &MediaOwner,
    version: u64,
    wall_ms: u64,
) -> Result<()> {
    for dimension in [
        MediaDimension::QueuedOperationsGlobal,
        MediaDimension::QueuedOperationsPerSession,
    ] {
        let name = dimension_name(dimension);
        let (kind, scope_id) = scope_identity(dimension.scope_policy().scope, owner, id);
        let amount=conn.query_row("SELECT COALESCE(SUM(delta),0) FROM media_reservation_deltas WHERE reservation_id=?1 AND dimension=?2",params![id,name],|r|row_u64(r,0))?;
        if amount > 0 {
            mutate_counter(conn, kind, &scope_id, &name, -i64::try_from(amount)?)?;
            record_delta(
                conn,
                id,
                version,
                &name,
                kind,
                &scope_id,
                amount,
                -i64::try_from(amount)?,
                "promote",
                wall_ms,
            )?;
        }
    }
    Ok(())
}
fn release_dimension_balance(
    conn: &rusqlite::Connection,
    id: &str,
    version: u64,
    dimension: &str,
    wall_ms: u64,
) -> Result<()> {
    let mut statement=conn.prepare("SELECT scope_kind,scope_id,SUM(delta) FROM media_reservation_deltas WHERE reservation_id=?1 AND dimension=?2 GROUP BY scope_kind,scope_id")?;
    let rows = statement
        .query_map(params![id, dimension], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (kind, scope_id, balance) in rows.into_iter().filter(|(_, _, balance)| *balance > 0) {
        mutate_counter(conn, &kind, &scope_id, dimension, -balance)?;
        record_delta(
            conn,
            id,
            version,
            dimension,
            &kind,
            &scope_id,
            u64::try_from(balance)?,
            -balance,
            "release",
            wall_ms,
        )?;
    }
    Ok(())
}
fn deletion_is_proven(conn: &rusqlite::Connection, id: &str, dimension: &str) -> Result<bool> {
    if conn
        .query_row(
            "SELECT 1 FROM media_cleanup_attestations WHERE reservation_id=?1 AND dimension=?2",
            params![id, dimension],
            |_| Ok(()),
        )
        .optional()?
        .is_some()
    {
        return Ok(true);
    }
    let(total,deleted)=conn.query_row("SELECT COUNT(*),COALESCE(SUM(CASE WHEN deletion_tombstone_checksum IS NOT NULL THEN 1 ELSE 0 END),0) FROM media_artifact_facts WHERE reservation_id=?1 AND dimension=?2",params![id,dimension],|r|Ok((row_u64(r,0)?,row_u64(r,1)?)))?;
    Ok(total > 0 && total == deleted)
}
fn external_reconciliation_is_terminal(conn: &rusqlite::Connection, id: &str) -> Result<bool> {
    let state:Option<String>=conn.query_row("SELECT j.state FROM media_reservations r JOIN external_journal_operations j ON j.operation_id=r.external_operation_id WHERE r.reservation_id=?1",[id],|r|r.get(0)).optional()?;
    Ok(state.is_some_and(|value| {
        matches!(
            value.as_str(),
            "rejected"
                | "cancelled"
                | "expired"
                | "completed_after_cancel"
                | "succeeded"
                | "failed"
        )
    }))
}
fn release_restart_dimensions(
    conn: &rusqlite::Connection,
    id: &str,
    version: u64,
    wall_ms: u64,
) -> Result<()> {
    for dimension in [
        MediaDimension::QueuedOperationsGlobal,
        MediaDimension::QueuedOperationsPerSession,
        MediaDimension::LocalCpuJobsGlobal,
    ] {
        release_dimension_balance(conn, id, version, &dimension_name(dimension), wall_ms)?;
    }
    Ok(())
}
fn has_releasable_balance(conn: &rusqlite::Connection, id: &str) -> Result<bool> {
    let mut statement = conn.prepare("SELECT dimension,SUM(delta) FROM media_reservation_deltas WHERE reservation_id=?1 GROUP BY dimension HAVING SUM(delta)>0")?;
    for row in statement.query_map([id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
        let (dimension, balance) = row?;
        if balance <= 0 {
            continue;
        }
        if let Ok(parsed) =
            serde_json::from_value::<MediaDimension>(serde_json::Value::String(dimension))
            && parsed.scope_policy().release
                != cockpit_config::config::media_budget::MediaRelease::Never
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn classify_storage_error(error: anyhow::Error) -> LedgerError {
    let text = error.to_string();
    if text.contains("accounting_blocked") {
        LedgerError::AccountingBlocked
    } else if text.contains("stale_version") {
        LedgerError::StaleVersion
    } else if text.contains("invalid_transition") || text.contains("deadline_expired") {
        LedgerError::InvalidTransition
    } else if text.contains("overflow") || text.contains("out of range") {
        LedgerError::Overflow
    } else if let Some(rest) = text.strip_prefix("media_denied:") {
        let mut p = rest.split(':');
        let dimension = p.next().unwrap_or("unknown").to_owned();
        let retryable =
            serde_json::from_value::<MediaDimension>(serde_json::Value::String(dimension.clone()))
                .ok()
                .is_some_and(|value| {
                    value.scope_policy().accumulation == MediaAccumulation::Additive
                        && value.scope_policy().release.is_reclaimable()
                });
        LedgerError::Denied(MediaDenial {
            dimension,
            requested: p.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            effective: p.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            current: p.next().and_then(|v| v.parse().ok()).unwrap_or(0),
            scope: p.next().unwrap_or("unknown").into(),
            source: p.next().unwrap_or("unknown").into(),
            code: "media_resource_denied",
            retryable,
        })
    } else {
        LedgerError::Storage(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountingDiagnosis {
    pub scope_kind: String,
    pub scope_id: String,
    pub affected_dimensions: Vec<String>,
    pub source_delta_rows: u64,
    pub artifact_rows: u64,
    pub current_counter_digest: String,
    pub rebuilt_counter_digest: String,
    pub journal_blockers: u64,
    pub manifest_blockers: u64,
    pub block_generation: u64,
    pub repair_plan_digest: String,
}
pub fn stable_counter_digest(values: &BTreeMap<String, u64>) -> String {
    let mut h = Sha256::new();
    for (k, v) in values {
        h.update(k.as_bytes());
        h.update([0]);
        h.update(v.to_be_bytes());
    }
    lowercase_hex(&h.finalize())
}

fn rebuild_counters(
    conn: &rusqlite::Connection,
    kind: &str,
    id: &str,
) -> Result<BTreeMap<String, u64>> {
    let mut statement=conn.prepare("SELECT dimension,SUM(delta) FROM media_reservation_deltas WHERE scope_kind=?1 AND scope_id=?2 GROUP BY dimension ORDER BY dimension")?;
    let mut result = BTreeMap::new();
    for row in statement.query_map(params![kind, id], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })? {
        let (dimension, total) = row?;
        if total < 0 {
            bail!("accounting repair negative total");
        }
        result.insert(dimension, u64::try_from(total)?);
    }
    Ok(result)
}
fn diagnose_connection(
    conn: &rusqlite::Connection,
    kind: &str,
    id: &str,
) -> Result<AccountingDiagnosis> {
    let rebuilt = rebuild_counters(conn, kind, id)?;
    let mut current = BTreeMap::new();
    let mut statement=conn.prepare("SELECT dimension,charged FROM media_resource_counters WHERE scope_kind=?1 AND scope_id=?2 ORDER BY dimension")?;
    for row in statement.query_map(params![kind, id], |r| {
        Ok((r.get::<_, String>(0)?, row_u64(r, 1)?))
    })? {
        let (k, v) = row?;
        current.insert(k, v);
    }
    let source_delta_rows = conn.query_row(
        "SELECT COUNT(*) FROM media_reservation_deltas WHERE scope_kind=?1 AND scope_id=?2",
        params![kind, id],
        |r| row_u64(r, 0),
    )?;
    let artifact_rows=conn.query_row("SELECT COUNT(*) FROM media_artifact_facts a JOIN media_reservations r ON r.reservation_id=a.reservation_id WHERE (?1='global') OR (?1='project' AND r.project_id=?2) OR (?1='session' AND r.owner_session_key=?2)",params![kind,id],|r|row_u64(r,0))?;
    let journal_blockers=conn.query_row("SELECT COUNT(*) FROM media_reservations WHERE state IN ('dispatching_external','external_pending','reconciling_external','cancellation_requested') AND ((?1='global') OR (?1='project' AND project_id=?2) OR (?1='session' AND owner_session_key=?2))",params![kind,id],|r|row_u64(r,0))?;
    let manifest_blockers=conn.query_row("SELECT COUNT(*) FROM media_reservations r WHERE r.quarantined=1 AND NOT EXISTS(SELECT 1 FROM media_artifact_facts a WHERE a.reservation_id=r.reservation_id) AND ((?1='global') OR (?1='project' AND r.project_id=?2) OR (?1='session' AND r.owner_session_key=?2))",params![kind,id],|r|row_u64(r,0))?;
    let block_generation = conn
        .query_row(
            "SELECT generation FROM media_accounting_blocks WHERE scope_kind=?1 AND scope_id=?2",
            params![kind, id],
            |r| row_u64(r, 0),
        )
        .optional()?
        .unwrap_or(0);
    let current_counter_digest = stable_counter_digest(&current);
    let rebuilt_counter_digest = stable_counter_digest(&rebuilt);
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(id.as_bytes());
    hasher.update(block_generation.to_be_bytes());
    hasher.update(source_delta_rows.to_be_bytes());
    hasher.update(artifact_rows.to_be_bytes());
    hasher.update(rebuilt_counter_digest.as_bytes());
    let repair_plan_digest = lowercase_hex(&hasher.finalize());
    Ok(AccountingDiagnosis {
        scope_kind: kind.into(),
        scope_id: id.into(),
        affected_dimensions: rebuilt.keys().cloned().collect(),
        source_delta_rows,
        artifact_rows,
        current_counter_digest,
        rebuilt_counter_digest,
        journal_blockers,
        manifest_blockers,
        block_generation,
        repair_plan_digest,
    })
}
fn repair_request_digest(request: &AccountingRepairRequest) -> String {
    let mut h = Sha256::new();
    for value in [
        &request.scope_kind,
        &request.scope_id,
        &request.repair_plan_digest,
        &request.idempotency_key,
    ] {
        h.update(value.as_bytes());
        h.update([0]);
    }
    h.update(request.expected_block_generation.to_be_bytes());
    lowercase_hex(&h.finalize())
}
fn finish_repair(
    conn: &rusqlite::Connection,
    id: &str,
    outcome: AccountingRepairOutcome,
    digest: Option<String>,
    wall_ms: u64,
) -> Result<AccountingRepairOutcome> {
    let current: String = conn.query_row(
        "SELECT state FROM media_repair_attempts WHERE attempt_id=?1",
        [id],
        |row| row.get(0),
    )?;
    if current == "planned" {
        conn.execute(
            "UPDATE media_repair_attempts SET state='rebuilding',updated_wall_ms=?2 WHERE attempt_id=?1",
            params![id, sqlite_i64(wall_ms)?],
        )?;
    }
    if current != "verifying" {
        conn.execute(
            "UPDATE media_repair_attempts SET state='verifying',updated_wall_ms=?2 WHERE attempt_id=?1",
            params![id, sqlite_i64(wall_ms)?],
        )?;
    }
    let state = if outcome == AccountingRepairOutcome::Committed {
        "committed"
    } else {
        "failed"
    };
    conn.execute("UPDATE media_repair_attempts SET state=?1,outcome=?2,rebuilt_counter_digest=?3,updated_wall_ms=?4 WHERE attempt_id=?5",params![state,outcome.code(),digest,sqlite_i64(wall_ms)?,id])?;
    Ok(outcome)
}
fn parse_repair_outcome(code: &str) -> AccountingRepairOutcome {
    match code {
        "accounting_repair_committed" => AccountingRepairOutcome::Committed,
        "accounting_repair_conflict" => AccountingRepairOutcome::Conflict,
        "accounting_repair_source_changed" => AccountingRepairOutcome::SourceChanged,
        "accounting_repair_overflow" => AccountingRepairOutcome::Overflow,
        "accounting_repair_unauthorized" => AccountingRepairOutcome::Unauthorized,
        _ => AccountingRepairOutcome::NotProvable,
    }
}
fn validate_repair_scope(scope: &str) -> Result<(), LedgerError> {
    if matches!(scope, "global" | "project" | "session") {
        Ok(())
    } else {
        Err(LedgerError::Storage(anyhow!(
            "invalid accounting repair scope"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_config::config::media_budget::{MediaEvaluationRequest, MediaResourcePolicy};
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Clock(AtomicU64);
    impl MonotonicClock for Clock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }
    struct Cleanup;
    impl LocalExpiryCleanup for Cleanup {
        fn kill_reap_and_cleanup(&self, _: &str) -> Result<String> {
            Ok("cleanup-proof".into())
        }
    }
    fn plan(dimension: MediaDimension, requested: u64, limit: Option<u64>) -> MediaReservationPlan {
        MediaResourcePolicy::default()
            .evaluate(MediaEvaluationRequest {
                dimension,
                requested: Some(requested),
                current_scope: 0,
                profile: None,
                adapter_limit: None,
                request_limit: limit,
            })
            .unwrap()
    }
    fn request(id: &str, plans: Vec<MediaReservationPlan>) -> ReserveRequest {
        ReserveRequest {
            reservation_id: id.into(),
            recovery_id: format!("recovery-{id}"),
            owner: MediaOwner {
                project_id: "project".into(),
                session_id: format!("session-{id}"),
            },
            operation: "generate".into(),
            purpose: "test".into(),
            plans,
            wall_ms: 1,
        }
    }

    #[tokio::test]
    async fn media_budget_reservation_atomic() {
        let db = Db::open_in_memory().unwrap();
        let ledger = MediaReservationLedger::new(db.clone(), Arc::new(Clock(AtomicU64::new(0))));
        let plans = vec![
            plan(MediaDimension::QueuedOperationsPerSession, 1, Some(1)),
            plan(MediaDimension::QueuedOperationsGlobal, 1, Some(1)),
            plan(MediaDimension::OperationDeadlineSeconds, 10, None),
        ];
        ledger.reserve(request("a", plans.clone())).await.unwrap();
        assert!(matches!(
            ledger.reserve(request("b", plans)).await,
            Err(LedgerError::Denied(_))
        ));
        let charged=db.read(|conn|Ok(conn.query_row("SELECT charged FROM media_resource_counters WHERE scope_kind='global' AND dimension='queued_operations_global'",[],|r|row_u64(r,0))?)).await.unwrap();
        assert_eq!(charged, 1);
    }

    #[tokio::test]
    async fn media_budget_deadline() {
        let db = Db::open_in_memory().unwrap();
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let ledger = MediaReservationLedger::new(db, clock.clone());
        let receipt = ledger
            .reserve(request(
                "deadline",
                vec![
                    plan(MediaDimension::QueuedOperationsGlobal, 1, None),
                    plan(MediaDimension::QueuedOperationsPerSession, 1, None),
                    plan(MediaDimension::OperationDeadlineSeconds, 1, None),
                ],
            ))
            .await
            .unwrap();
        clock.0.store(1_000, Ordering::SeqCst);
        assert_eq!(
            ledger
                .expire_before_handoff(&receipt.reservation_id, receipt.version, 2, &Cleanup)
                .await
                .unwrap()
                .state,
            ReservationState::Released
        );
    }

    #[tokio::test]
    async fn media_budget_overage() {
        let db = Db::open_in_memory().unwrap();
        let ledger = MediaReservationLedger::new(db, Arc::new(Clock(AtomicU64::new(0))));
        let receipt = ledger
            .reserve(request(
                "overage",
                vec![
                    plan(MediaDimension::EncodedBytesPerObject, 10, None),
                    plan(MediaDimension::OperationDeadlineSeconds, 10, None),
                ],
            ))
            .await
            .unwrap();
        let settling = ledger
            .transition(
                &receipt.reservation_id,
                receipt.version,
                ReservationState::Settling,
                2,
            )
            .await
            .unwrap();
        let over = ledger
            .reconcile_actual(
                &receipt.reservation_id,
                settling.version,
                MediaDimension::EncodedBytesPerObject,
                11,
                false,
                2,
            )
            .await
            .unwrap();
        assert_eq!(over.state, ReservationState::OverageQuarantined);
        assert!(
            !ledger
                .publication_allowed(&over.reservation_id)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn media_budget_restart_recovery() {
        let db = Db::open_in_memory().unwrap();
        let ledger = MediaReservationLedger::new(db.clone(), Arc::new(Clock(AtomicU64::new(0))));
        ledger
            .reserve(request(
                "restart",
                vec![
                    plan(MediaDimension::QueuedOperationsGlobal, 1, None),
                    plan(MediaDimension::QueuedOperationsPerSession, 1, None),
                    plan(MediaDimension::RetainedBytesPerSession, 5, None),
                    plan(MediaDimension::OperationDeadlineSeconds, 10, None),
                ],
            ))
            .await
            .unwrap();
        assert_eq!(ledger.recover_after_restart(2).await.unwrap(), 1);
        let values: Vec<(String, u64)> = db
            .read(|conn| {
                let mut s = conn.prepare(
                    "SELECT dimension,charged FROM media_resource_counters ORDER BY dimension",
                )?;
                Ok(
                    s.query_map([], |r| Ok((r.get::<_, String>(0)?, row_u64(r, 1)?)))?
                        .collect::<rusqlite::Result<Vec<_>>>()?,
                )
            })
            .await
            .unwrap();
        assert!(values.contains(&("retained_bytes_per_session".into(), 5)));
        assert!(values.contains(&("queued_operations_global".into(), 0)));
    }

    #[test]
    fn media_budget_queue_lifecycle() {
        use ReservationState as S;
        let allowed = [
            (S::ReservedQueued, S::ExecutingLocal),
            (S::ReservedQueued, S::DispatchingExternal),
            (S::ReservedQueued, S::CancellationRequested),
            (S::ReservedQueued, S::Settling),
            (S::ExecutingLocal, S::DispatchingExternal),
            (S::ExecutingLocal, S::CancellationRequested),
            (S::ExecutingLocal, S::Settling),
            (S::ExecutingLocal, S::OverageQuarantined),
            (S::ExecutingLocal, S::AccountingCorrupt),
            (S::DispatchingExternal, S::ExternalPending),
            (S::DispatchingExternal, S::CancellationRequested),
            (S::DispatchingExternal, S::Settling),
            (S::DispatchingExternal, S::OverageQuarantined),
            (S::DispatchingExternal, S::AccountingCorrupt),
            (S::ExternalPending, S::ReconcilingExternal),
            (S::ExternalPending, S::CancellationRequested),
            (S::ExternalPending, S::Settling),
            (S::ExternalPending, S::OverageQuarantined),
            (S::ExternalPending, S::AccountingCorrupt),
            (S::ReconcilingExternal, S::ExternalPending),
            (S::ReconcilingExternal, S::CancellationRequested),
            (S::ReconcilingExternal, S::Settling),
            (S::ReconcilingExternal, S::OverageQuarantined),
            (S::ReconcilingExternal, S::AccountingCorrupt),
            (S::CancellationRequested, S::ExternalPending),
            (S::CancellationRequested, S::ReconcilingExternal),
            (S::CancellationRequested, S::Settling),
            (S::CancellationRequested, S::OverageQuarantined),
            (S::CancellationRequested, S::AccountingCorrupt),
            (S::OverageQuarantined, S::Settling),
            (S::OverageQuarantined, S::AccountingCorrupt),
            (S::Settling, S::Released),
            (S::Settling, S::OverageQuarantined),
            (S::Settling, S::AccountingCorrupt),
        ];
        let states = [
            S::ReservedQueued,
            S::ExecutingLocal,
            S::DispatchingExternal,
            S::ExternalPending,
            S::ReconcilingExternal,
            S::CancellationRequested,
            S::OverageQuarantined,
            S::Settling,
            S::Released,
            S::AccountingCorrupt,
        ];
        for from in states {
            for to in states {
                assert_eq!(
                    from.allows(to),
                    allowed.contains(&(from, to)),
                    "{from:?}->{to:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn media_budget_queue_fairness() {
        let ledger = MediaReservationLedger::new(
            Db::open_in_memory().unwrap(),
            Arc::new(Clock(AtomicU64::new(0))),
        );
        let plans = || {
            vec![
                plan(MediaDimension::QueuedOperationsGlobal, 1, None),
                plan(MediaDimension::QueuedOperationsPerSession, 1, None),
                plan(MediaDimension::OperationDeadlineSeconds, 10, None),
            ]
        };
        for (id, session) in [("a1", "a"), ("a2", "a"), ("b1", "b"), ("b2", "b")] {
            let mut value = request(id, plans());
            value.owner.session_id = session.into();
            ledger.reserve(value).await.unwrap();
        }
        assert_eq!(
            [
                ledger.next_fair_candidate().await.unwrap(),
                ledger.next_fair_candidate().await.unwrap(),
                ledger.next_fair_candidate().await.unwrap(),
                ledger.next_fair_candidate().await.unwrap()
            ],
            [
                Some("a1".into()),
                Some("b1".into()),
                Some("a1".into()),
                Some("b1".into())
            ]
        );
    }

    #[test]
    fn media_budget_accounting_repair() {
        let mut counters = BTreeMap::from([("bytes".to_owned(), 1)]);
        let first = stable_counter_digest(&counters);
        assert_eq!(first, stable_counter_digest(&counters));
        counters.insert("bytes".into(), 2);
        assert_ne!(first, stable_counter_digest(&counters));
        for outcome in [
            AccountingRepairOutcome::Committed,
            AccountingRepairOutcome::Conflict,
            AccountingRepairOutcome::NotProvable,
            AccountingRepairOutcome::SourceChanged,
            AccountingRepairOutcome::Overflow,
            AccountingRepairOutcome::Unauthorized,
        ] {
            assert!(outcome.code().starts_with("accounting_repair_"));
        }
    }

    #[test]
    fn media_budget_denials_are_redacted() {
        let denial = MediaDenial {
            code: "media_resource_denied",
            dimension: "retained_bytes_per_session".into(),
            requested: 2,
            effective: 1,
            current: 1,
            scope: "session".into(),
            source: "config".into(),
            retryable: true,
        };
        let json = serde_json::to_string(&denial).unwrap();
        for forbidden in ["path", "url", "credential", "prompt"] {
            assert!(!json.contains(forbidden));
        }
    }
}
