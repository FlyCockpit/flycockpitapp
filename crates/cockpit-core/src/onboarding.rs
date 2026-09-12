//! Daemon-owned onboarding transition authority.
//!
//! The authority is deliberately vault-free.  It persists only redacted state
//! and hands the one-shot passphrase to the daemon composition boundary; it
//! never writes configuration or credential files itself.

use anyhow::{Context, Result, bail};
use cockpit_proto::{
    ApplyOnboardingSecureIntent, ApplyOnboardingTransition, BeginOrReopenOnboarding,
    HostCapabilitySnapshot, OnboardingBootstrapSnapshot, OnboardingBootstrapState,
    OnboardingReceiptStatus, OnboardingSecurePlacement, OnboardingStage, OnboardingTransitionKind,
    OnboardingTransitionReceipt,
};
use zeroize::Zeroizing;

use crate::db::Db;
use crate::db::onboarding::{
    OnboardingBootstrapState as DbBootstrapState, OnboardingReceiptRow,
    OnboardingReceiptStatus as DbReceiptStatus, OnboardingSnapshotRow, OnboardingStage as DbStage,
};

#[derive(Clone)]
pub struct OnboardingAuthority {
    db: Db,
}

impl OnboardingAuthority {
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    pub async fn snapshot(
        &self,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<Option<OnboardingBootstrapSnapshot>> {
        self.db
            .onboarding_snapshot()
            .await?
            .map(|row| project(row, host_capabilities, None))
            .transpose()
    }

    pub async fn begin_or_reopen(
        &self,
        request: BeginOrReopenOnboarding,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        if request.client_operation_id.is_empty() {
            bail!("onboarding client operation id is required");
        }
        let (row, receipt) = self
            .db
            .onboarding_begin_or_reopen(
                request.expected_revision,
                request.client_operation_id,
                request.reentry,
            )
            .await?;
        let receipt = receipt(receipt);
        let snapshot = project(row, host_capabilities, Some(receipt.clone()))?;
        Ok((snapshot, receipt))
    }

    /// Apply an intent through the only secret-bearing onboarding boundary.
    ///
    /// The durable record is written before the callback runs, but the
    /// passphrase itself is moved directly into the callback and is never
    /// retained by this authority.  A callback failure deliberately leaves a
    /// `materializing` checkpoint for boot reconciliation; callers must not
    /// turn that uncertain effect into a blind retry.
    pub async fn apply_secure_intent_with<F>(
        &self,
        request: ApplyOnboardingSecureIntent,
        host_capabilities: HostCapabilitySnapshot,
        materialize: F,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)>
    where
        F: FnOnce(OnboardingSecurePlacement, Option<Zeroizing<String>>) -> Result<()>,
    {
        let client_operation_id = request.client_operation_id.clone();
        let placement = request.placement;
        let passphrase = request.passphrase.map(|value| value.into_zeroizing());
        let (pending, _) = self
            .record_secure_intent(
                request.run_id,
                request.attempt_id,
                request.expected_revision,
                client_operation_id.clone(),
                placement,
                passphrase.is_some(),
                host_capabilities.clone(),
            )
            .await?;
        materialize(placement, passphrase)?;
        self.mark_secure_store_ready(
            &pending,
            format!("{client_operation_id}:ready"),
            host_capabilities,
        )
        .await
    }

    async fn record_secure_intent(
        &self,
        run_id: uuid::Uuid,
        attempt_id: uuid::Uuid,
        expected_revision: u64,
        client_operation_id: String,
        placement: OnboardingSecurePlacement,
        passphrase_present: bool,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        match placement {
            OnboardingSecurePlacement::PassphraseFile if !passphrase_present => {
                bail!("passphrase placement requires a confirmed passphrase")
            }
            OnboardingSecurePlacement::PassphraseFile => {}
            _ if passphrase_present => bail!("passphrase is only valid for passphrase placement"),
            _ => {}
        }
        let current = self
            .db
            .onboarding_snapshot()
            .await?
            .context("no onboarding run exists")?;
        if current.run_id != run_id
            || current.attempt_id != attempt_id
            || current.revision != expected_revision
        {
            bail!("onboarding revision conflict");
        }
        if current.stage != DbStage::SecureStore {
            bail!("secure-store intent is only valid at the secure-store stage");
        }
        let (row, receipt_row) = self
            .db
            .onboarding_transition(
                current,
                client_operation_id,
                DbStage::SecureStore,
                DbBootstrapState::Materializing,
                false,
                Some(placement(placement)),
            )
            .await?;
        let receipt = receipt(receipt_row);
        let snapshot = project(row, host_capabilities, Some(receipt.clone()))?;
        Ok((snapshot, receipt))
    }

    pub async fn mark_secure_store_ready(
        &self,
        expected: &OnboardingBootstrapSnapshot,
        client_operation_id: String,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        let current = self
            .db
            .onboarding_snapshot()
            .await?
            .context("no onboarding run exists")?;
        if current.run_id != expected.run_id
            || current.attempt_id != expected.attempt_id
            || current.revision != expected.revision
        {
            bail!("onboarding revision conflict");
        }
        let selected_secure_placement = current.selected_secure_placement;
        let (row, receipt_row) = self
            .db
            .onboarding_transition(
                current,
                client_operation_id,
                DbStage::Provider,
                DbBootstrapState::Ready,
                false,
                selected_secure_placement,
            )
            .await?;
        let receipt = receipt(receipt_row);
        let snapshot = project(row, host_capabilities, Some(receipt.clone()))?;
        Ok((snapshot, receipt))
    }

    /// Advance only a legal, vault-ready stage.  This is intentionally a
    /// metadata reducer: provider/OAuth/agent effects must first settle in
    /// their existing daemon authority and then be correlated here by the
    /// dispatcher, rather than copied into onboarding storage.
    pub async fn apply_transition(
        &self,
        request: ApplyOnboardingTransition,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        let current = self
            .db
            .onboarding_snapshot()
            .await?
            .context("no onboarding run exists")?;
        if current.run_id != request.run_id
            || current.attempt_id != request.attempt_id
            || current.revision != request.expected_revision
        {
            bail!("onboarding revision conflict");
        }
        let (stage, limited_mode) = ordinary_transition(&current, request.transition)?;
        let selected_secure_placement = current.selected_secure_placement;
        let (row, receipt_row) = self
            .db
            .onboarding_transition(
                current,
                request.client_operation_id,
                stage,
                DbBootstrapState::Ready,
                limited_mode,
                selected_secure_placement,
            )
            .await?;
        let receipt = receipt(receipt_row);
        let snapshot = project(row, host_capabilities, Some(receipt.clone()))?;
        Ok((snapshot, receipt))
    }
}

fn ordinary_transition(
    current: &OnboardingSnapshotRow,
    transition: OnboardingTransitionKind,
) -> Result<(DbStage, bool)> {
    let ready = current.bootstrap_state == DbBootstrapState::Ready
        || matches!(current.stage, DbStage::Welcome | DbStage::Profile);
    let next = match transition {
        OnboardingTransitionKind::DeferProvider if current.stage == DbStage::Provider && ready => {
            return Ok((DbStage::Provider, true));
        }
        OnboardingTransitionKind::Advance if ready => match current.stage {
            DbStage::Welcome => DbStage::Profile,
            DbStage::Profile => DbStage::SecureStore,
            DbStage::Provider => DbStage::Model,
            DbStage::Model => DbStage::Agent,
            DbStage::Agent => DbStage::Lifetime,
            DbStage::Lifetime => DbStage::Complete,
            _ => bail!("onboarding stage cannot advance without a correlated daemon settlement"),
        },
        OnboardingTransitionKind::Back if ready => match current.stage {
            DbStage::Profile => DbStage::Welcome,
            DbStage::SecureStore => DbStage::Profile,
            DbStage::Provider => DbStage::SecureStore,
            DbStage::Model => DbStage::Provider,
            DbStage::Agent => DbStage::Model,
            DbStage::Lifetime => DbStage::Agent,
            DbStage::Complete => DbStage::Lifetime,
            DbStage::Welcome => bail!("onboarding is already at the first stage"),
        },
        OnboardingTransitionKind::Complete if ready && current.stage == DbStage::Lifetime => {
            DbStage::Complete
        }
        _ => bail!("onboarding transition is not legal for the current checkpoint"),
    };
    Ok((next, false))
}

fn placement(value: OnboardingSecurePlacement) -> crate::db::onboarding::OnboardingSecurePlacement {
    match value {
        OnboardingSecurePlacement::Automatic => {
            crate::db::onboarding::OnboardingSecurePlacement::Automatic
        }
        OnboardingSecurePlacement::Keyring => {
            crate::db::onboarding::OnboardingSecurePlacement::Keyring
        }
        OnboardingSecurePlacement::PassphraseFile => {
            crate::db::onboarding::OnboardingSecurePlacement::PassphraseFile
        }
        OnboardingSecurePlacement::MachineBoundFile => {
            crate::db::onboarding::OnboardingSecurePlacement::MachineBoundFile
        }
    }
}

fn project(
    row: OnboardingSnapshotRow,
    host_capabilities: HostCapabilitySnapshot,
    last_receipt: Option<OnboardingTransitionReceipt>,
) -> Result<OnboardingBootstrapSnapshot> {
    Ok(OnboardingBootstrapSnapshot {
        run_id: row.run_id,
        attempt_id: row.attempt_id,
        revision: row.revision,
        stage: stage(row.stage),
        bootstrap_state: bootstrap_state(row.bootstrap_state),
        limited_mode: row.limited_mode,
        lifetime_selection: row.lifetime_selection,
        host_capabilities,
        last_receipt,
    })
}

fn stage(value: DbStage) -> OnboardingStage {
    match value {
        DbStage::Welcome => OnboardingStage::Welcome,
        DbStage::Profile => OnboardingStage::Profile,
        DbStage::SecureStore => OnboardingStage::SecureStore,
        DbStage::Provider => OnboardingStage::Provider,
        DbStage::Model => OnboardingStage::Model,
        DbStage::Agent => OnboardingStage::Agent,
        DbStage::Lifetime => OnboardingStage::Lifetime,
        DbStage::Complete => OnboardingStage::Complete,
    }
}

fn bootstrap_state(value: DbBootstrapState) -> OnboardingBootstrapState {
    match value {
        DbBootstrapState::AwaitingChoice => OnboardingBootstrapState::AwaitingChoice,
        DbBootstrapState::AwaitingPassphrase => OnboardingBootstrapState::AwaitingPassphrase,
        DbBootstrapState::Materializing => OnboardingBootstrapState::Materializing,
        DbBootstrapState::Ready => OnboardingBootstrapState::Ready,
        DbBootstrapState::Failed => OnboardingBootstrapState::Failed,
    }
}

fn receipt(value: OnboardingReceiptRow) -> OnboardingTransitionReceipt {
    OnboardingTransitionReceipt {
        run_id: value.run_id,
        attempt_id: value.attempt_id,
        consumed_revision: value.consumed_revision,
        receipt_id: value.receipt_id,
        status: match value.status {
            DbReceiptStatus::Pending => OnboardingReceiptStatus::Pending,
            DbReceiptStatus::Committed => OnboardingReceiptStatus::Committed,
            DbReceiptStatus::Rejected => OnboardingReceiptStatus::Rejected,
            DbReceiptStatus::Unknown => OnboardingReceiptStatus::Unknown,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::SensitiveOnboardingPassphrase;

    fn capabilities() -> HostCapabilitySnapshot {
        HostCapabilitySnapshot::unpublished()
    }

    async fn secure_stage(authority: &OnboardingAuthority) -> OnboardingBootstrapSnapshot {
        let (welcome, _) = authority
            .begin_or_reopen(
                BeginOrReopenOnboarding {
                    expected_revision: None,
                    client_operation_id: "begin".into(),
                    reentry: false,
                },
                capabilities(),
            )
            .await
            .unwrap();
        let (profile, _) = authority
            .apply_transition(
                ApplyOnboardingTransition {
                    run_id: welcome.run_id,
                    attempt_id: welcome.attempt_id,
                    expected_revision: welcome.revision,
                    client_operation_id: "welcome".into(),
                    transition: OnboardingTransitionKind::Advance,
                },
                capabilities(),
            )
            .await
            .unwrap();
        authority
            .apply_transition(
                ApplyOnboardingTransition {
                    run_id: profile.run_id,
                    attempt_id: profile.attempt_id,
                    expected_revision: profile.revision,
                    client_operation_id: "profile".into(),
                    transition: OnboardingTransitionKind::Advance,
                },
                capabilities(),
            )
            .await
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn passphrase_is_consumed_once_and_never_persisted_in_onboarding_rows() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db.clone());
        let secure = secure_stage(&authority).await;
        let (ready, _) = authority
            .apply_secure_intent_with(
                ApplyOnboardingSecureIntent {
                    run_id: secure.run_id,
                    attempt_id: secure.attempt_id,
                    expected_revision: secure.revision,
                    client_operation_id: "passphrase-intent".into(),
                    placement: OnboardingSecurePlacement::PassphraseFile,
                    passphrase: Some(SensitiveOnboardingPassphrase::new(
                        "passphrase-canary".into(),
                    )),
                },
                capabilities(),
                |placement, passphrase| {
                    assert_eq!(placement, OnboardingSecurePlacement::PassphraseFile);
                    assert_eq!(passphrase.as_deref(), Some("passphrase-canary"));
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(ready.stage, OnboardingStage::Provider);
        assert_eq!(ready.bootstrap_state, OnboardingBootstrapState::Ready);
        let persisted = db
            .read(|conn| {
                let mut statement = conn.prepare(
                    "SELECT group_concat(run_id || ':' || active_attempt_id || ':' || coalesce(selected_secure_placement, ''), '|') FROM onboarding_runs",
                )?;
                statement.query_row([], |row| row.get::<_, Option<String>>(0))
            })
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(!persisted.contains("passphrase-canary"));
        assert!(
            !serde_json::to_string(&ready)
                .unwrap()
                .contains("passphrase-canary")
        );
    }

    #[tokio::test]
    async fn provider_defer_is_durable_but_cancel_is_not_a_transition() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db);
        let secure = secure_stage(&authority).await;
        let (provider, _) = authority
            .apply_secure_intent_with(
                ApplyOnboardingSecureIntent {
                    run_id: secure.run_id,
                    attempt_id: secure.attempt_id,
                    expected_revision: secure.revision,
                    client_operation_id: "keyring-intent".into(),
                    placement: OnboardingSecurePlacement::Keyring,
                    passphrase: None,
                },
                capabilities(),
                |_placement, passphrase| {
                    assert!(passphrase.is_none());
                    Ok(())
                },
            )
            .await
            .unwrap();
        let (deferred, _) = authority
            .apply_transition(
                ApplyOnboardingTransition {
                    run_id: provider.run_id,
                    attempt_id: provider.attempt_id,
                    expected_revision: provider.revision,
                    client_operation_id: "defer".into(),
                    transition: OnboardingTransitionKind::DeferProvider,
                },
                capabilities(),
            )
            .await
            .unwrap();
        assert_eq!(deferred.stage, OnboardingStage::Provider);
        assert!(deferred.limited_mode);
    }
}
