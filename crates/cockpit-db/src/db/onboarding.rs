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
    pub selected_secure_placement: Option<OnboardingSecurePlacement>,
    pub limited_mode: bool,
    pub lifetime_selection: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingSecurePlacement {
    Automatic,
    Keyring,
    PassphraseFile,
    MachineBoundFile,
}

impl OnboardingSecurePlacement {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Automatic => "automatic",
            Self::Keyring => "keyring",
            Self::PassphraseFile => "passphrase_file",
            Self::MachineBoundFile => "machine_bound_file",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "automatic" => Ok(Self::Automatic),
            "keyring" => Ok(Self::Keyring),
            "passphrase_file" => Ok(Self::PassphraseFile),
            "machine_bound_file" => Ok(Self::MachineBoundFile),
            _ => bail!("invalid persisted onboarding secure placement"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingReceiptRow {
    pub receipt_id: Uuid,
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub client_operation_id: String,
    pub consumed_revision: u64,
    pub status: OnboardingReceiptStatus,
    /// True only when this call returned a previously durable operation.
    /// This is storage-local metadata and is never projected onto the wire.
    pub replayed: bool,
}

fn uuid(value: String, field: &str) -> Result<Uuid> {
    Uuid::parse_str(&value).with_context(|| format!("invalid persisted onboarding {field}"))
}

fn snapshot_conn(conn: &rusqlite::Connection) -> Result<Option<OnboardingSnapshotRow>> {
    conn.query_row(
        "SELECT run_id, active_attempt_id, revision, stage, bootstrap_state, selected_secure_placement, limited_mode, lifetime_selection
         FROM onboarding_runs WHERE id = 1",
        [],
        |row| {
            let revision: i64 = row.get(2)?;
            let stage: String = row.get(3)?;
            let bootstrap_state: String = row.get(4)?;
            Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?, revision, stage,
                bootstrap_state, row.get::<_, Option<String>>(5)?, row.get::<_, i64>(6)? != 0, row.get(7)?,
            ))
        },
    )
    .optional()?
    .map(|(run_id, attempt_id, revision, stage, bootstrap_state, selected_secure_placement, limited_mode, lifetime_selection)| {
        Ok(OnboardingSnapshotRow {
            run_id: uuid(run_id, "run id")?,
            attempt_id: uuid(attempt_id, "attempt id")?,
            revision: u64::try_from(revision).context("invalid onboarding revision")?,
            stage: OnboardingStage::parse(&stage)?,
            bootstrap_state: OnboardingBootstrapState::parse(&bootstrap_state)?,
            selected_secure_placement: selected_secure_placement
                .as_deref()
                .map(OnboardingSecurePlacement::parse)
                .transpose()?,
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
        reentry: bool,
    ) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
        self.write(move |conn| {
            begin_or_reopen_conn(conn, expected_revision, &client_operation_id, reentry)
        })
        .await
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
        selected_secure_placement: Option<OnboardingSecurePlacement>,
    ) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
        self.onboarding_transition_with_receipt_status(
            snapshot,
            client_operation_id,
            next_stage,
            bootstrap_state,
            limited_mode,
            selected_secure_placement,
            OnboardingReceiptStatus::Committed,
        )
        .await
    }

    /// The secure-vault hand-off reserves its revision before performing an
    /// external effect.  Its receipt stays pending until that effect reports
    /// success, so a crash can be reconciled without pretending it committed.
    pub async fn onboarding_transition_pending(
        &self,
        snapshot: OnboardingSnapshotRow,
        client_operation_id: String,
        next_stage: OnboardingStage,
        bootstrap_state: OnboardingBootstrapState,
        limited_mode: bool,
        selected_secure_placement: Option<OnboardingSecurePlacement>,
    ) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
        self.onboarding_transition_with_receipt_status(
            snapshot,
            client_operation_id,
            next_stage,
            bootstrap_state,
            limited_mode,
            selected_secure_placement,
            OnboardingReceiptStatus::Pending,
        )
        .await
    }

    async fn onboarding_transition_with_receipt_status(
        &self,
        snapshot: OnboardingSnapshotRow,
        client_operation_id: String,
        next_stage: OnboardingStage,
        bootstrap_state: OnboardingBootstrapState,
        limited_mode: bool,
        selected_secure_placement: Option<OnboardingSecurePlacement>,
        receipt_status: OnboardingReceiptStatus,
    ) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
        self.write(move |conn| {
            transition_conn(
                conn,
                &snapshot,
                &client_operation_id,
                next_stage,
                bootstrap_state,
                limited_mode,
                selected_secure_placement,
                receipt_status,
            )
        })
        .await
    }

    /// Return an exact transition receipt, validating its immutable operation
    /// fingerprint.  This is the only safe replay lookup: callers cannot use
    /// an operation id from a different transition as a generic status key.
    pub async fn onboarding_transition_receipt(
        &self,
        run_id: Uuid,
        attempt_id: Uuid,
        client_operation_id: String,
        next_stage: OnboardingStage,
        bootstrap_state: OnboardingBootstrapState,
        limited_mode: bool,
        selected_secure_placement: Option<OnboardingSecurePlacement>,
    ) -> Result<Option<(OnboardingSnapshotRow, OnboardingReceiptRow)>> {
        self.read(move |conn| {
            transition_receipt_conn(
                conn,
                run_id,
                attempt_id,
                &client_operation_id,
                next_stage,
                bootstrap_state,
                limited_mode,
                selected_secure_placement,
            )
        })
        .await
    }

    /// Move only a pending receipt to a terminal state.  The guarded update
    /// prevents a late callback from rewriting an already-settled receipt.
    pub async fn onboarding_set_pending_receipt_status(
        &self,
        receipt_id: Uuid,
        status: OnboardingReceiptStatus,
    ) -> Result<()> {
        if status == OnboardingReceiptStatus::Pending {
            bail!("onboarding receipt must settle to a terminal status");
        }
        self.write(move |conn| {
            let changed = conn.execute(
                "UPDATE onboarding_receipts SET status = ?1 WHERE receipt_id = ?2 AND status = 'pending'",
                params![status.as_str(), receipt_id.to_string()],
            )?;
            if changed != 1 {
                bail!("onboarding receipt is not pending");
            }
            Ok(())
        })
        .await
    }
}

fn begin_or_reopen_conn(
    conn: &rusqlite::Connection,
    expected_revision: Option<u64>,
    client_operation_id: &str,
    reentry: bool,
) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
    if let Some(existing) = snapshot_conn(conn)? {
        let expected = expected_revision.context("onboarding revision is required for reopen")?;
        if existing.revision != expected {
            bail!("onboarding revision conflict");
        }
        return reopen_conn(conn, &existing, client_operation_id, reentry);
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
         (receipt_id, run_id, attempt_id, client_operation_id, consumed_revision, operation_kind, operation_digest, status, created_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, 0, 'begin', ?5, 'committed', ?6)",
        params![receipt_id.to_string(), run_id.to_string(), attempt_id.to_string(), client_operation_id, digest_begin(reentry), now],
    )?;
    let snapshot = snapshot_conn(conn)?.context("onboarding run did not persist")?;
    Ok((
        snapshot,
        OnboardingReceiptRow {
            receipt_id,
            run_id,
            attempt_id,
            client_operation_id: client_operation_id.into(),
            consumed_revision: 0,
            status: OnboardingReceiptStatus::Committed,
            replayed: false,
        },
    ))
}

fn transition_conn(
    conn: &rusqlite::Connection,
    current: &OnboardingSnapshotRow,
    client_operation_id: &str,
    next_stage: OnboardingStage,
    bootstrap_state: OnboardingBootstrapState,
    limited_mode: bool,
    selected_secure_placement: Option<OnboardingSecurePlacement>,
    receipt_status: OnboardingReceiptStatus,
) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
    if client_operation_id.is_empty() || client_operation_id.len() > 128 {
        bail!("invalid onboarding client operation id");
    }
    let replay = conn
        .query_row(
            "SELECT receipt_id, consumed_revision, operation_kind, operation_digest, status FROM onboarding_receipts
         WHERE run_id = ?1 AND attempt_id = ?2 AND client_operation_id = ?3",
            params![
                current.run_id.to_string(),
                current.attempt_id.to_string(),
                client_operation_id
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let (operation_kind, operation_digest) = transition_fingerprint(
        next_stage,
        bootstrap_state,
        limited_mode,
        selected_secure_placement,
    );
    if let Some((receipt_id, consumed_revision, replay_kind, replay_digest, status)) = replay {
        if replay_kind != operation_kind || replay_digest != operation_digest {
            bail!("onboarding client operation id was reused for a different transition");
        }
        let refreshed = snapshot_conn(conn)?.context("onboarding run did not persist")?;
        return Ok((
            refreshed,
            OnboardingReceiptRow {
                receipt_id: uuid(receipt_id, "receipt id")?,
                run_id: current.run_id,
                attempt_id: current.attempt_id,
                client_operation_id: client_operation_id.into(),
                consumed_revision: u64::try_from(consumed_revision)?,
                status: OnboardingReceiptStatus::parse(&status)?,
                replayed: true,
            },
        ));
    }
    let next_revision = current
        .revision
        .checked_add(1)
        .context("onboarding revision overflow")?;
    let now = Utc::now().timestamp_millis();
    let changed = conn.execute(
        "UPDATE onboarding_runs SET revision = ?1, stage = ?2, bootstrap_state = ?3, limited_mode = ?4, selected_secure_placement = ?5, updated_at_unix_ms = ?6
         WHERE id = 1 AND run_id = ?7 AND active_attempt_id = ?8 AND revision = ?9",
        params![i64::try_from(next_revision)?, next_stage.as_str(), bootstrap_state.as_str(), if limited_mode { 1_i64 } else { 0_i64 }, selected_secure_placement.map(OnboardingSecurePlacement::as_str), now, current.run_id.to_string(), current.attempt_id.to_string(), i64::try_from(current.revision)?],
    )?;
    if changed != 1 {
        bail!("onboarding revision conflict");
    }
    let receipt_id = Uuid::new_v4();
    conn.execute(
        "INSERT INTO onboarding_receipts
         (receipt_id, run_id, attempt_id, client_operation_id, consumed_revision, operation_kind, operation_digest, status, created_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![receipt_id.to_string(), current.run_id.to_string(), current.attempt_id.to_string(), client_operation_id, i64::try_from(current.revision)?, operation_kind, operation_digest, receipt_status.as_str(), now],
    )?;
    let snapshot = snapshot_conn(conn)?.context("onboarding transition did not persist")?;
    Ok((
        snapshot,
        OnboardingReceiptRow {
            receipt_id,
            run_id: current.run_id,
            attempt_id: current.attempt_id,
            client_operation_id: client_operation_id.into(),
            consumed_revision: current.revision,
            status: receipt_status,
            replayed: false,
        },
    ))
}

fn transition_receipt_conn(
    conn: &rusqlite::Connection,
    run_id: Uuid,
    attempt_id: Uuid,
    client_operation_id: &str,
    next_stage: OnboardingStage,
    bootstrap_state: OnboardingBootstrapState,
    limited_mode: bool,
    selected_secure_placement: Option<OnboardingSecurePlacement>,
) -> Result<Option<(OnboardingSnapshotRow, OnboardingReceiptRow)>> {
    let (operation_kind, operation_digest) = transition_fingerprint(
        next_stage,
        bootstrap_state,
        limited_mode,
        selected_secure_placement,
    );
    let receipt = conn
        .query_row(
            "SELECT receipt_id, consumed_revision, operation_kind, operation_digest, status
             FROM onboarding_receipts
             WHERE run_id = ?1 AND attempt_id = ?2 AND client_operation_id = ?3",
            params![
                run_id.to_string(),
                attempt_id.to_string(),
                client_operation_id
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((receipt_id, consumed_revision, stored_kind, stored_digest, status)) = receipt else {
        return Ok(None);
    };
    if stored_kind != operation_kind || stored_digest != operation_digest {
        bail!("onboarding client operation id was reused for a different transition");
    }
    let snapshot = snapshot_conn(conn)?.context("onboarding run did not persist")?;
    Ok(Some((
        snapshot,
        OnboardingReceiptRow {
            receipt_id: uuid(receipt_id, "receipt id")?,
            run_id,
            attempt_id,
            client_operation_id: client_operation_id.into(),
            consumed_revision: u64::try_from(consumed_revision)?,
            status: OnboardingReceiptStatus::parse(&status)?,
            replayed: true,
        },
    )))
}

fn reopen_conn(
    conn: &rusqlite::Connection,
    current: &OnboardingSnapshotRow,
    client_operation_id: &str,
    reentry: bool,
) -> Result<(OnboardingSnapshotRow, OnboardingReceiptRow)> {
    if client_operation_id.is_empty() || client_operation_id.len() > 128 {
        bail!("invalid onboarding client operation id");
    }
    let digest = digest_begin(reentry);
    let replay = conn.query_row(
        "SELECT receipt_id, consumed_revision, operation_digest, status FROM onboarding_receipts
         WHERE run_id = ?1 AND attempt_id = ?2 AND client_operation_id = ?3",
        params![current.run_id.to_string(), current.attempt_id.to_string(), client_operation_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?)),
    ).optional()?;
    if let Some((receipt_id, consumed_revision, replay_digest, status)) = replay {
        if replay_digest != digest {
            bail!("onboarding client operation id was reused for a different begin request");
        }
        return Ok((
            snapshot_conn(conn)?.context("onboarding run did not persist")?,
            OnboardingReceiptRow {
                receipt_id: uuid(receipt_id, "receipt id")?,
                run_id: current.run_id,
                attempt_id: current.attempt_id,
                client_operation_id: client_operation_id.into(),
                consumed_revision: u64::try_from(consumed_revision)?,
                status: OnboardingReceiptStatus::parse(&status)?,
                replayed: true,
            },
        ));
    }
    if current.stage == OnboardingStage::Complete && !reentry {
        let receipt_id = Uuid::new_v4();
        let now = Utc::now().timestamp_millis();
        conn.execute(
            "INSERT INTO onboarding_receipts (receipt_id, run_id, attempt_id, client_operation_id, consumed_revision, operation_kind, operation_digest, status, created_at_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, 'begin', ?6, 'committed', ?7)",
            params![receipt_id.to_string(), current.run_id.to_string(), current.attempt_id.to_string(), client_operation_id, i64::try_from(current.revision)?, digest, now],
        )?;
        return Ok((
            current.clone(),
            OnboardingReceiptRow {
                receipt_id,
                run_id: current.run_id,
                attempt_id: current.attempt_id,
                client_operation_id: client_operation_id.into(),
                consumed_revision: current.revision,
                status: OnboardingReceiptStatus::Committed,
                replayed: false,
            },
        ));
    }
    let next_revision = current
        .revision
        .checked_add(1)
        .context("onboarding revision overflow")?;
    let next_attempt_id = Uuid::new_v4();
    let receipt_id = Uuid::new_v4();
    let now = Utc::now().timestamp_millis();
    let changed = conn.execute(
        "UPDATE onboarding_runs SET active_attempt_id = ?1, revision = ?2, updated_at_unix_ms = ?3
         WHERE id = 1 AND run_id = ?4 AND active_attempt_id = ?5 AND revision = ?6",
        params![
            next_attempt_id.to_string(),
            i64::try_from(next_revision)?,
            now,
            current.run_id.to_string(),
            current.attempt_id.to_string(),
            i64::try_from(current.revision)?
        ],
    )?;
    if changed != 1 {
        bail!("onboarding revision conflict");
    }
    conn.execute("UPDATE onboarding_attempts SET status = 'superseded', closed_revision = ?1 WHERE attempt_id = ?2 AND status = 'active'", params![i64::try_from(next_revision)?, current.attempt_id.to_string()])?;
    conn.execute("INSERT INTO onboarding_attempts (attempt_id, run_id, opened_revision, status, created_at_unix_ms) VALUES (?1, ?2, ?3, 'active', ?4)", params![next_attempt_id.to_string(), current.run_id.to_string(), i64::try_from(next_revision)?, now])?;
    conn.execute(
        "INSERT INTO onboarding_receipts (receipt_id, run_id, attempt_id, client_operation_id, consumed_revision, operation_kind, operation_digest, status, created_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, 'begin', ?6, 'committed', ?7)",
        params![receipt_id.to_string(), current.run_id.to_string(), next_attempt_id.to_string(), client_operation_id, i64::try_from(current.revision)?, digest, now],
    )?;
    let snapshot = snapshot_conn(conn)?.context("onboarding reentry did not persist")?;
    Ok((
        snapshot,
        OnboardingReceiptRow {
            receipt_id,
            run_id: current.run_id,
            attempt_id: next_attempt_id,
            client_operation_id: client_operation_id.into(),
            consumed_revision: current.revision,
            status: OnboardingReceiptStatus::Committed,
            replayed: false,
        },
    ))
}

fn digest_begin(reentry: bool) -> String {
    transition_digest(&format!("begin:{reentry}"))
}

fn transition_fingerprint(
    stage: OnboardingStage,
    state: OnboardingBootstrapState,
    limited: bool,
    placement: Option<OnboardingSecurePlacement>,
) -> (&'static str, String) {
    (
        "transition",
        transition_digest(&format!(
            "{}:{}:{}:{}",
            stage.as_str(),
            state.as_str(),
            limited,
            placement
                .map(OnboardingSecurePlacement::as_str)
                .unwrap_or("-")
        )),
    )
}

fn transition_digest(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transition_is_revision_bound_and_terminal_replay_is_idempotent() {
        let db = Db::open_in_memory_async().await.unwrap();
        let (initial, _) = db
            .onboarding_begin_or_reopen(None, "begin".into(), false)
            .await
            .unwrap();
        assert_eq!(initial.revision, 0);
        assert_eq!(initial.stage, OnboardingStage::Welcome);
        assert_eq!(
            initial.bootstrap_state,
            OnboardingBootstrapState::AwaitingChoice
        );

        let (after, first) = db
            .onboarding_transition(
                initial.clone(),
                "select-keyring".into(),
                OnboardingStage::SecureStore,
                OnboardingBootstrapState::Materializing,
                false,
                Some(OnboardingSecurePlacement::Keyring),
            )
            .await
            .unwrap();
        assert_eq!(after.revision, 1);
        assert_eq!(first.status, OnboardingReceiptStatus::Committed);

        let (replayed, replay_receipt) = db
            .onboarding_transition(
                initial.clone(),
                "select-keyring".into(),
                OnboardingStage::SecureStore,
                OnboardingBootstrapState::Materializing,
                false,
                Some(OnboardingSecurePlacement::Keyring),
            )
            .await
            .unwrap();
        assert_eq!(replayed, after);
        assert_eq!(replay_receipt.receipt_id, first.receipt_id);

        let error = db
            .onboarding_transition(
                initial,
                "different-operation".into(),
                OnboardingStage::Provider,
                OnboardingBootstrapState::Ready,
                false,
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("revision conflict"));
        assert_eq!(db.onboarding_snapshot().await.unwrap(), Some(after));
    }

    #[tokio::test]
    async fn reopen_fences_the_old_attempt_without_overwriting_its_receipts() {
        let db = Db::open_in_memory_async().await.unwrap();
        let (initial, _) = db
            .onboarding_begin_or_reopen(None, "begin".into(), false)
            .await
            .unwrap();
        let (secured, receipt) = db
            .onboarding_transition(
                initial.clone(),
                "secure".into(),
                OnboardingStage::SecureStore,
                OnboardingBootstrapState::Materializing,
                false,
                Some(OnboardingSecurePlacement::MachineBoundFile),
            )
            .await
            .unwrap();
        let (reopened, reopen_receipt) = db
            .onboarding_begin_or_reopen(Some(secured.revision), "reopen".into(), true)
            .await
            .unwrap();
        assert_eq!(reopened.run_id, secured.run_id);
        assert_ne!(reopened.attempt_id, secured.attempt_id);
        assert_eq!(reopened.revision, secured.revision + 1);
        assert_eq!(
            reopened.selected_secure_placement,
            secured.selected_secure_placement
        );
        assert_eq!(reopen_receipt.attempt_id, reopened.attempt_id);

        let replay = db
            .onboarding_transition(
                secured,
                "secure".into(),
                OnboardingStage::SecureStore,
                OnboardingBootstrapState::Materializing,
                false,
                Some(OnboardingSecurePlacement::MachineBoundFile),
            )
            .await
            .unwrap();
        assert_eq!(replay.1.receipt_id, receipt.receipt_id);
        assert_eq!(replay.0, reopened);
    }

    #[tokio::test]
    async fn operation_id_cannot_be_reused_for_a_different_transition() {
        let db = Db::open_in_memory_async().await.unwrap();
        let (initial, _) = db
            .onboarding_begin_or_reopen(None, "begin".into(), false)
            .await
            .unwrap();
        db.onboarding_transition(
            initial.clone(),
            "one-operation".into(),
            OnboardingStage::SecureStore,
            OnboardingBootstrapState::Materializing,
            false,
            Some(OnboardingSecurePlacement::Keyring),
        )
        .await
        .unwrap();
        let error = db
            .onboarding_transition(
                initial,
                "one-operation".into(),
                OnboardingStage::SecureStore,
                OnboardingBootstrapState::Materializing,
                false,
                Some(OnboardingSecurePlacement::MachineBoundFile),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reused"));
    }
}
