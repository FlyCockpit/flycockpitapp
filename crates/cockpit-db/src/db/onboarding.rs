//! Durable, vault-free storage for the user-global onboarding authority.
//!
//! This module never accepts secret values.  It is safe to construct during
//! locked-first-run boot, before a secret vault or redactor exists.

use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use crate::db::Db;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingStage {
    Welcome,
    Profile,
    SecureStore,
    Provider,
    Model,
    Agent,
    Lifetime,
    Complete,
}

impl OnboardingStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Welcome => "welcome",
            Self::Profile => "profile",
            Self::SecureStore => "secure_store",
            Self::Provider => "provider",
            Self::Model => "model",
            Self::Agent => "agent",
            Self::Lifetime => "lifetime",
            Self::Complete => "complete",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "welcome" => Ok(Self::Welcome),
            "profile" => Ok(Self::Profile),
            "secure_store" => Ok(Self::SecureStore),
            "provider" => Ok(Self::Provider),
            "model" => Ok(Self::Model),
            "agent" => Ok(Self::Agent),
            "lifetime" => Ok(Self::Lifetime),
            "complete" => Ok(Self::Complete),
            _ => bail!("invalid persisted onboarding stage"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingBootstrapState {
    AwaitingChoice,
    AwaitingPassphrase,
    Materializing,
    Ready,
    Failed,
}

impl OnboardingBootstrapState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingChoice => "awaiting_choice",
            Self::AwaitingPassphrase => "awaiting_passphrase",
            Self::Materializing => "materializing",
            Self::Ready => "ready",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "awaiting_choice" => Ok(Self::AwaitingChoice),
            "awaiting_passphrase" => Ok(Self::AwaitingPassphrase),
            "materializing" => Ok(Self::Materializing),
            "ready" => Ok(Self::Ready),
            "failed" => Ok(Self::Failed),
            _ => bail!("invalid persisted onboarding bootstrap state"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingReceiptStatus {
    Pending,
    Committed,
    Rejected,
    Unknown,
}

impl OnboardingReceiptStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Committed => "committed",
            Self::Rejected => "rejected",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "pending" => Ok(Self::Pending),
            "committed" => Ok(Self::Committed),
            "rejected" => Ok(Self::Rejected),
            "unknown" => Ok(Self::Unknown),
            _ => bail!("invalid persisted onboarding receipt status"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingSnapshotRow {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub revision: u64,
    pub stage: OnboardingStage,
    pub bootstrap_state: OnboardingBootstrapState,
    pub limited_mode: bool,
    pub lifetime_selection: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingReceiptRow {
    pub receipt_id: Uuid,
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub client_operation_id: String,
    pub consumed_revision: u64,
    pub status: OnboardingReceiptStatus,
}

fn uuid(value: String, field: &str) -> Result<Uuid> {
    Uuid::parse_str(&value).with_context(|| format!("invalid persisted onboarding {field}"))
}

fn snapshot_conn(conn: &rusqlite::Connection) -> Result<Option<OnboardingSnapshotRow>> {
    conn.query_row(
        "SELECT run_id, active_attempt_id, revision, stage, bootstrap_state, limited_mode, lifetime_selection
         FROM onboarding_runs WHERE id = 1",
        [],
        |row| {
            let revision: i64 = row.get(2)?;
            let stage: String = row.get(3)?;
            let bootstrap_state: String = row.get(4)?;
            Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?, revision, stage,
                bootstrap_state, row.get::<_, i64>(5)? != 0, row.get(6)?,
            ))
        },
    )
    .optional()?
    .map(|(run_id, attempt_id, revision, stage, bootstrap_state, limited_mode, lifetime_selection)| {
        Ok(OnboardingSnapshotRow {
            run_id: uuid(run_id, "run id")?,
            attempt_id: uuid(attempt_id, "attempt id")?,
            revision: u64::try_from(revision).context("invalid onboarding revision")?,
            stage: OnboardingStage::parse(&stage)?,
            bootstrap_state: OnboardingBootstrapState::parse(&bootstrap_state)?,
            limited_mode,
            lifetime_selection,
        })
    })
    .transpose()
}

impl Db {
    pub async fn onboarding_snapshot(&self) -> Result<Option<OnboardingSnapshotRow>> {
        self.read(snapshot_conn).await
    }

    /// Begin the first durable run or reopen the active run using revision CAS.
    pub async fn onboarding_begin_or_reopen(
        &self,
        expected_revision: Option<u64>,
        client_operation_id: String,
    ) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
        self.write(move |conn| begin_or_reopen_conn(conn, expected_revision, &client_operation_id)).await
    }

    /// Consume one revision and persist an idempotent receipt.  This is the
    /// sole transition funnel; callers cannot update a stage without an
    /// expected revision and client operation id.
    pub async fn onboarding_transition(
        &self,
        snapshot: OnboardingSnapshotRow,
        client_operation_id: String,
        next_stage: OnboardingStage,
        bootstrap_state: OnboardingBootstrapState,
        limited_mode: bool,
    ) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
        self.write(move |conn| transition_conn(
            conn, &snapshot, &client_operation_id, next_stage, bootstrap_state, limited_mode,
        )).await
    }
}

fn begin_or_reopen_conn(
    conn: &rusqlite::Connection,
    expected_revision: Option<u64>,
    client_operation_id: &str,
) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
    if let Some(existing) = snapshot_conn(conn)? {
        let expected = expected_revision.context("onboarding revision is required for reopen")?;
        if existing.revision != expected {
            bail!("onboarding revision conflict");
        }
        return transition_conn(
            conn, &existing, client_operation_id, existing.stage, existing.bootstrap_state, existing.limited_mode,
        );
    }
    if expected_revision.is_some() {
        bail!("onboarding revision conflict");
    }
    if client_operation_id.is_empty() || client_operation_id.len() > 128 {
        bail!("invalid onboarding client operation id");
    }
    let run_id = Uuid::new_v4();
    let attempt_id = Uuid::new_v4();
    let receipt_id = Uuid::new_v4();
    let now = Utc::now().timestamp_millis();
    conn.execute(
        "INSERT INTO onboarding_runs
         (id, run_id, active_attempt_id, revision, stage, bootstrap_state, limited_mode, created_at_unix_ms, updated_at_unix_ms)
         VALUES (1, ?1, ?2, 0, 'welcome', 'awaiting_choice', 0, ?3, ?3)",
        params![run_id.to_string(), attempt_id.to_string(), now],
    )?;
    conn.execute(
        "INSERT INTO onboarding_attempts (attempt_id, run_id, opened_revision, status, created_at_unix_ms)
         VALUES (?1, ?2, 0, 'active', ?3)",
        params![attempt_id.to_string(), run_id.to_string(), now],
    )?;
    conn.execute(
        "INSERT INTO onboarding_receipts
         (receipt_id, run_id, attempt_id, client_operation_id, consumed_revision, status, created_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, 0, 'committed', ?5)",
        params![receipt_id.to_string(), run_id.to_string(), attempt_id.to_string(), client_operation_id, now],
    )?;
    let snapshot = snapshot_conn(conn)?.context("onboarding run did not persist")?;
    Ok((snapshot, OnboardingReceiptRow { receipt_id, run_id, attempt_id, client_operation_id: client_operation_id.into(), consumed_revision: 0, status: OnboardingReceiptStatus::Committed }))
}

fn transition_conn(
    conn: &rusqlite::Connection,
    current: &OnboardingSnapshotRow,
    client_operation_id: &str,
    next_stage: OnboardingStage,
    bootstrap_state: OnboardingBootstrapState,
    limited_mode: bool,
) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
    if client_operation_id.is_empty() || client_operation_id.len() > 128 {
        bail!("invalid onboarding client operation id");
    }
    let replay = conn.query_row(
        "SELECT receipt_id, consumed_revision, status FROM onboarding_receipts
         WHERE run_id = ?1 AND attempt_id = ?2 AND client_operation_id = ?3",
        params![current.run_id.to_string(), current.attempt_id.to_string(), client_operation_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?)),
    ).optional()?;
    if let Some((receipt_id, consumed_revision, status)) = replay {
        return Ok((current.clone(), OnboardingReceiptRow {
            receipt_id: uuid(receipt_id, "receipt id")?, run_id: current.run_id, attempt_id: current.attempt_id,
            client_operation_id: client_operation_id.into(), consumed_revision: u64::try_from(consumed_revision)?,
            status: OnboardingReceiptStatus::parse(&status)?,
        }));
    }
    let next_revision = current.revision.checked_add(1).context("onboarding revision overflow")?;
    let now = Utc::now().timestamp_millis();
    let changed = conn.execute(
        "UPDATE onboarding_runs SET revision = ?1, stage = ?2, bootstrap_state = ?3, limited_mode = ?4, updated_at_unix_ms = ?5
         WHERE id = 1 AND run_id = ?6 AND active_attempt_id = ?7 AND revision = ?8",
        params![i64::try_from(next_revision)?, next_stage.as_str(), bootstrap_state.as_str(), if limited_mode { 1_i64 } else { 0_i64 }, now, current.run_id.to_string(), current.attempt_id.to_string(), i64::try_from(current.revision)?],
    )?;
    if changed != 1 { bail!("onboarding revision conflict"); }
    let receipt_id = Uuid::new_v4();
    conn.execute(
        "INSERT INTO onboarding_receipts
         (receipt_id, run_id, attempt_id, client_operation_id, consumed_revision, status, created_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, 'committed', ?6)",
        params![receipt_id.to_string(), current.run_id.to_string(), current.attempt_id.to_string(), client_operation_id, i64::try_from(current.revision)?, now],
    )?;
    let snapshot = snapshot_conn(conn)?.context("onboarding transition did not persist")?;
    Ok((snapshot, OnboardingReceiptRow { receipt_id, run_id: current.run_id, attempt_id: current.attempt_id, client_operation_id: client_operation_id.into(), consumed_revision: current.revision, status: OnboardingReceiptStatus::Committed }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transition_is_revision_bound_and_terminal_replay_is_idempotent() {
        let db = Db::open_in_memory_async().await.unwrap();
        let (initial, _) = db
            .onboarding_begin_or_reopen(None, "begin".into())
            .await
            .unwrap();
        assert_eq!(initial.revision, 0);
        assert_eq!(initial.stage, OnboardingStage::Welcome);
        assert_eq!(initial.bootstrap_state, OnboardingBootstrapState::AwaitingChoice);

        let (after, first) = db
            .onboarding_transition(
                initial.clone(),
                "select-keyring".into(),
                OnboardingStage::SecureStore,
                OnboardingBootstrapState::Materializing,
                false,
            )
            .await
            .unwrap();
        assert_eq!(after.revision, 1);
        assert_eq!(first.status, OnboardingReceiptStatus::Committed);

        let (replayed, replay_receipt) = db
            .onboarding_transition(
                initial.clone(),
                "select-keyring".into(),
                OnboardingStage::Provider,
                OnboardingBootstrapState::Ready,
                true,
            )
            .await
            .unwrap();
        assert_eq!(replayed, initial);
        assert_eq!(replay_receipt.receipt_id, first.receipt_id);

        let error = db
            .onboarding_transition(
                initial,
                "different-operation".into(),
                OnboardingStage::Provider,
                OnboardingBootstrapState::Ready,
                false,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("revision conflict"));
        assert_eq!(db.onboarding_snapshot().await.unwrap(), Some(after));
    }
}
