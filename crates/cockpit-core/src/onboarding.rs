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

fn stage_entry_config_generation() -> u64 {
    crate::daemon::server::inventory::current_config_generation()
}

pub fn secure_vault_open_options(
    placement: OnboardingSecurePlacement,
    mut passphrase: Option<Zeroizing<String>>,
) -> Result<crate::secure_key::SecretVaultOpenOptions> {
    let first_run_intent = match placement {
        OnboardingSecurePlacement::Automatic => {
            crate::secure_key::FirstRunSecretStoreIntent::Automatic
        }
        OnboardingSecurePlacement::Keyring => crate::secure_key::FirstRunSecretStoreIntent::Keyring,
        OnboardingSecurePlacement::PassphraseFile => {
            crate::secure_key::FirstRunSecretStoreIntent::FilePassphrase
        }
        OnboardingSecurePlacement::MachineBoundFile => {
            crate::secure_key::FirstRunSecretStoreIntent::FileMachineBound
        }
    };
    let passphrase = passphrase
        .as_mut()
        .map(|value| {
            crate::secure_key::Passphrase::from_bytes(std::mem::take(&mut **value).into_bytes())
        })
        .transpose()?;
    Ok(crate::secure_key::SecretVaultOpenOptions {
        first_run_intent,
        passphrase,
    })
}

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

    pub async fn receipt(
        &self,
        query: cockpit_proto::OnboardingReceiptQuery,
    ) -> Result<Option<OnboardingTransitionReceipt>> {
        if query.client_operation_id.is_empty() {
            bail!("onboarding client operation id is required");
        }
        let row = self
            .db
            .onboarding_receipt(query.run_id, query.attempt_id, query.client_operation_id)
            .await?;
        Ok(row.map(receipt))
    }

    pub async fn begin_or_reopen(
        &self,
        request: BeginOrReopenOnboarding,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        if request.client_operation_id.is_empty() {
            bail!("onboarding client operation id is required");
        }
        let (row, receipt_row) = self
            .db
            .onboarding_begin_or_reopen(
                request.expected_revision,
                request.client_operation_id,
                request.reentry,
            )
            .await?;
        let receipt = receipt(receipt_row);
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
        vault_authority_exists: bool,
        materialize: F,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)>
    where
        F: FnOnce(OnboardingSecurePlacement, Option<Zeroizing<String>>) -> Result<()>,
    {
        if vault_authority_exists {
            bail!("secure-store choice is already committed");
        }
        let client_operation_id = request.client_operation_id.clone();
        let placement = request.placement;
        let passphrase = request.passphrase.map(|value| value.into_zeroizing());
        if let Some((snapshot, prior_receipt)) = self
            .db
            .onboarding_transition_receipt(
                request.run_id,
                request.attempt_id,
                client_operation_id.clone(),
                DbStage::SecureStore,
                DbBootstrapState::Materializing,
                false,
                Some(db_placement(placement)),
            )
            .await?
        {
            let receipt = receipt(prior_receipt);
            return Ok((
                project(snapshot, host_capabilities, Some(receipt.clone()))?,
                receipt,
            ));
        }
        let (pending, pending_receipt) = self
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
        if let Err(error) = materialize(placement, passphrase) {
            self.db
                .onboarding_set_pending_receipt_status(
                    pending_receipt.receipt_id,
                    DbReceiptStatus::Unknown,
                )
                .await
                .context("recording uncertain secure-store materialization")?;
            return Err(error);
        }
        self.db
            .onboarding_set_pending_receipt_status(
                pending_receipt.receipt_id,
                DbReceiptStatus::Committed,
            )
            .await?;
        let (ready, _) = self
            .mark_secure_store_ready(
                &pending,
                format!("{client_operation_id}:ready"),
                host_capabilities.clone(),
            )
            .await?;
        let terminal = OnboardingTransitionReceipt {
            status: OnboardingReceiptStatus::Committed,
            ..pending_receipt
        };
        Ok((ready, terminal))
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
        let capability_id = match placement {
            OnboardingSecurePlacement::Automatic | OnboardingSecurePlacement::Keyring => {
                "secret_store.keyring"
            }
            OnboardingSecurePlacement::PassphraseFile
            | OnboardingSecurePlacement::MachineBoundFile => "secret_store.file",
        };
        let capability = host_capabilities
            .feature(capability_id)
            .context("secure-store capability has not been published")?;
        if !capability.state.is_available() {
            let guidance = capability
                .fix_command
                .as_deref()
                .or(capability.remedy_text.as_deref())
                .unwrap_or(capability.reason.as_str());
            bail!("selected secure-store placement is unavailable: {guidance}");
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
            .onboarding_transition_pending(
                current,
                client_operation_id,
                DbStage::SecureStore,
                DbBootstrapState::Materializing,
                false,
                Some(db_placement(placement)),
                stage_entry_config_generation(),
            )
            .await?;
        let receipt = receipt(receipt_row);
        let snapshot = project(row, host_capabilities, Some(receipt.clone()))?;
        Ok((snapshot, receipt))
    }

    /// Reconcile the only crash-sensitive bootstrap checkpoint before ready
    /// services are built.  A durable vault authority is proof that the
    /// selected placement can be opened normally.  Without one, a passphrase
    /// choice cannot be replayed because its bytes were intentionally never
    /// persisted; the user must submit it again.  Other interrupted choices
    /// return to an explicit choice state rather than silently falling back.
    pub async fn reconcile_materializing_secure_intent(
        &self,
        vault_authority_exists: bool,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<Option<OnboardingBootstrapSnapshot>> {
        let Some(current) = self.db.onboarding_snapshot().await? else {
            return Ok(None);
        };
        if current.bootstrap_state != DbBootstrapState::Materializing {
            return Ok(Some(project(current, host_capabilities, None)?));
        }
        let (stage, state, placement) = if vault_authority_exists {
            (
                DbStage::Provider,
                DbBootstrapState::Ready,
                current.selected_secure_placement,
            )
        } else if current.selected_secure_placement
            == Some(crate::db::onboarding::OnboardingSecurePlacement::PassphraseFile)
        {
            (
                DbStage::SecureStore,
                DbBootstrapState::AwaitingPassphrase,
                current.selected_secure_placement,
            )
        } else {
            (DbStage::SecureStore, DbBootstrapState::AwaitingChoice, None)
        };
        let operation_id = format!("bootstrap-reconcile-{}", current.revision);
        let (snapshot, _) = self
            .db
            .onboarding_transition(
                current,
                operation_id,
                stage,
                state,
                false,
                placement,
                stage_entry_config_generation(),
            )
            .await?;
        Ok(Some(project(snapshot, host_capabilities, None)?))
    }

    pub async fn mark_ready_construction_failed(
        &self,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<OnboardingBootstrapSnapshot> {
        let current = self
            .db
            .onboarding_snapshot()
            .await?
            .context("no onboarding run exists")?;
        if current.bootstrap_state == DbBootstrapState::Failed {
            return project(current, host_capabilities, None);
        }
        let (row, _) = self
            .db
            .onboarding_transition(
                current,
                format!("ready-construction-failed-{}", current.revision),
                current.stage,
                DbBootstrapState::Failed,
                current.limited_mode,
                current.selected_secure_placement,
                stage_entry_config_generation(),
            )
            .await?;
        project(row, host_capabilities, None)
    }

    pub async fn mark_ready_construction_recovered(
        &self,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<()> {
        let current = self
            .db
            .onboarding_snapshot()
            .await?
            .context("no onboarding run exists")?;
        if current.bootstrap_state != DbBootstrapState::Failed {
            return Ok(());
        }
        self.db
            .onboarding_transition(
                current,
                format!("ready-construction-recovered-{}", current.revision),
                current.stage,
                DbBootstrapState::Ready,
                current.limited_mode,
                current.selected_secure_placement,
                stage_entry_config_generation(),
            )
            .await?;
        Ok(())
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
                stage_entry_config_generation(),
            )
            .await?;
        let receipt = receipt(receipt_row);
        let snapshot = project(row, host_capabilities, Some(receipt.clone()))?;
        Ok((snapshot, receipt))
    }

    /// Advance only a legal, vault-ready stage that does not require an
    /// external daemon settlement.  Provider, model, and agent advances must
    /// use [`Self::apply_settled_advance`] after dispatch validates the
    /// correlated terminal receipt.
    pub async fn apply_transition(
        &self,
        request: ApplyOnboardingTransition,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        if request.settlement.is_some() {
            bail!("settlement correlation is only valid for provider, model, or agent advance");
        }
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
        self.commit_transition(
            current,
            request.client_operation_id,
            stage,
            limited_mode,
            host_capabilities,
        )
        .await
    }

    /// Advance provider, model, or agent after dispatch has validated the
    /// exact external settlement referenced by `request.settlement`.
    pub async fn apply_settled_advance(
        &self,
        request: ApplyOnboardingTransition,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        let settlement = request
            .settlement
            .as_ref()
            .context("onboarding advance requires settlement correlation")?;
        if settlement.settlement_operation_id.is_empty()
            || settlement.settlement_operation_id.len() > 128
        {
            bail!("invalid onboarding settlement operation id");
        }
        if settlement.run_id != request.run_id
            || settlement.attempt_id != request.attempt_id
            || settlement.stage_revision != request.expected_revision
        {
            bail!("onboarding settlement does not match the active run checkpoint");
        }
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
        if request.transition != OnboardingTransitionKind::Advance {
            bail!("settlement correlation is only valid for advance");
        }
        let next = match current.stage {
            DbStage::Provider | DbStage::Model | DbStage::Agent => {
                settled_advance_stage(current.stage, settlement.provider_id.as_deref())?
            }
            _ => bail!("onboarding transition is not legal for the current checkpoint"),
        };
        self.commit_transition(
            current,
            request.client_operation_id,
            next,
            false,
            host_capabilities,
        )
        .await
    }

    async fn commit_transition(
        &self,
        current: OnboardingSnapshotRow,
        client_operation_id: String,
        stage: DbStage,
        limited_mode: bool,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        let selected_secure_placement = current.selected_secure_placement;
        let (row, receipt_row) = self
            .db
            .onboarding_transition(
                current,
                client_operation_id,
                stage,
                DbBootstrapState::Ready,
                limited_mode,
                selected_secure_placement,
                stage_entry_config_generation(),
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
            DbStage::Provider | DbStage::Model | DbStage::Agent => {
                bail!("onboarding stage cannot advance without a correlated daemon settlement");
            }
            DbStage::Lifetime => DbStage::Complete,
            _ => bail!("onboarding transition is not legal for the current checkpoint"),
        },
        OnboardingTransitionKind::Back if ready => match current.stage {
            DbStage::Profile => DbStage::Welcome,
            DbStage::SecureStore => DbStage::Profile,
            DbStage::Provider => {
                bail!("secure-store choice is committed and cannot be reopened through onboarding")
            }
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

fn settled_advance_stage(current: DbStage, provider_id: Option<&str>) -> Result<DbStage> {
    match current {
        DbStage::Provider => {
            if provider_id.is_none() {
                bail!("provider advance requires a settled provider identity");
            }
            Ok(DbStage::Model)
        }
        DbStage::Model => Ok(DbStage::Agent),
        DbStage::Agent => Ok(DbStage::Lifetime),
        _ => bail!("onboarding transition is not legal for the current checkpoint"),
    }
}

fn db_placement(
    value: OnboardingSecurePlacement,
) -> crate::db::onboarding::OnboardingSecurePlacement {
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
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn capabilities() -> HostCapabilitySnapshot {
        let mut snapshot = HostCapabilitySnapshot::unpublished();
        snapshot.features = ["secret_store.keyring", "secret_store.file"]
            .into_iter()
            .map(|id| cockpit_proto::FeatureCapabilityRow {
                id: id.into(),
                state: cockpit_proto::FeatureCapabilityState::Available,
                reason: "test capability available".into(),
                fix_command: None,
                remedy_text: None,
                dependency_ids: Vec::new(),
            })
            .collect();
        snapshot
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
                    settlement: None,
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
                    settlement: None,
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
                    passphrase: Some(
                        SensitiveOnboardingPassphrase::confirmed(
                            "passphrase-canary".into(),
                            "passphrase-canary".into(),
                        )
                        .unwrap(),
                    ),
                },
                capabilities(),
                false,
                |placement, passphrase| {
                    assert_eq!(placement, OnboardingSecurePlacement::PassphraseFile);
                    assert_eq!(
                        passphrase.as_ref().map(|value| value.as_str()),
                        Some("passphrase-canary")
                    );
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
                Ok(statement.query_row([], |row| row.get::<_, Option<String>>(0))?)
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
                false,
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
                    settlement: None,
                },
                capabilities(),
            )
            .await
            .unwrap();
        assert_eq!(deferred.stage, OnboardingStage::Provider);
        assert!(deferred.limited_mode);
    }

    #[tokio::test]
    async fn secure_intent_replay_never_materializes_the_vault_twice() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db);
        let secure = secure_stage(&authority).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = calls.clone();
        let request = |revision| ApplyOnboardingSecureIntent {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: revision,
            client_operation_id: "one-keyring-intent".into(),
            placement: OnboardingSecurePlacement::Keyring,
            passphrase: None,
        };
        let (ready, first) = authority
            .apply_secure_intent_with(
                request(secure.revision),
                capabilities(),
                false,
                move |_, _| {
                    first_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .unwrap();
        let (replayed, replay_receipt) = authority
            .apply_secure_intent_with(request(secure.revision), capabilities(), false, |_, _| {
                panic!("an exact onboarding replay must not re-materialize the vault")
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(replay_receipt.receipt_id, first.receipt_id);
        assert_eq!(replayed.revision, ready.revision);
        assert_eq!(replayed.stage, OnboardingStage::Provider);
    }

    #[tokio::test]
    async fn interrupted_passphrase_materialization_requires_a_new_sensitive_submission() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db.clone());
        let secure = secure_stage(&authority).await;
        let request = ApplyOnboardingSecureIntent {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: "interrupted-passphrase-intent".into(),
            placement: OnboardingSecurePlacement::PassphraseFile,
            passphrase: Some(
                SensitiveOnboardingPassphrase::confirmed(
                    "crash-canary".into(),
                    "crash-canary".into(),
                )
                .unwrap(),
            ),
        };
        let error = authority
            .apply_secure_intent_with(request, capabilities(), false, |_, _| {
                anyhow::bail!("materializer interrupted")
            })
            .await
            .expect_err("failed materialization must leave an uncertain checkpoint");
        assert!(error.to_string().contains("materializer interrupted"));
        let uncertain = authority
            .receipt(cockpit_proto::OnboardingReceiptQuery {
                run_id: secure.run_id,
                attempt_id: secure.attempt_id,
                client_operation_id: "interrupted-passphrase-intent".into(),
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(uncertain.status, OnboardingReceiptStatus::Unknown);
        let resumed = authority
            .reconcile_materializing_secure_intent(false, capabilities())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resumed.stage, OnboardingStage::SecureStore);
        assert_eq!(
            resumed.bootstrap_state,
            OnboardingBootstrapState::AwaitingPassphrase
        );
        let serialized_rows = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT group_concat(run_id || active_attempt_id || coalesce(selected_secure_placement, ''), '|') FROM onboarding_runs",
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )?)
            })
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(!serialized_rows.contains("crash-canary"));
        assert!(
            !serde_json::to_string(&resumed)
                .unwrap()
                .contains("crash-canary")
        );
    }

    #[tokio::test]
    async fn unavailable_keyring_requires_a_new_explicit_file_choice() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db);
        let secure = secure_stage(&authority).await;
        let mut unavailable = capabilities();
        let keyring = unavailable
            .features
            .iter_mut()
            .find(|feature| feature.id == "secret_store.keyring")
            .unwrap();
        keyring.state = cockpit_proto::FeatureCapabilityState::Missing;
        keyring.fix_command = Some("unlock-keyring".into());
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let error = authority
            .apply_secure_intent_with(
                ApplyOnboardingSecureIntent {
                    run_id: secure.run_id,
                    attempt_id: secure.attempt_id,
                    expected_revision: secure.revision,
                    client_operation_id: "keyring-choice".into(),
                    placement: OnboardingSecurePlacement::Automatic,
                    passphrase: None,
                },
                unavailable.clone(),
                false,
                move |_, _| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unlock-keyring"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let (ready, _) = authority
            .apply_secure_intent_with(
                ApplyOnboardingSecureIntent {
                    run_id: secure.run_id,
                    attempt_id: secure.attempt_id,
                    expected_revision: secure.revision,
                    client_operation_id: "explicit-file-choice".into(),
                    placement: OnboardingSecurePlacement::MachineBoundFile,
                    passphrase: None,
                },
                unavailable,
                false,
                |placement, _| {
                    assert_eq!(placement, OnboardingSecurePlacement::MachineBoundFile);
                    Ok(())
                },
            )
            .await
            .unwrap();
        assert_eq!(ready.stage, OnboardingStage::Provider);
    }

    #[tokio::test]
    async fn concurrent_clients_can_consume_one_revision_only() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db);
        let secure = secure_stage(&authority).await;
        let (provider, _) = authority
            .apply_secure_intent_with(
                ApplyOnboardingSecureIntent {
                    run_id: secure.run_id,
                    attempt_id: secure.attempt_id,
                    expected_revision: secure.revision,
                    client_operation_id: "secure".into(),
                    placement: OnboardingSecurePlacement::MachineBoundFile,
                    passphrase: None,
                },
                capabilities(),
                false,
                |_, _| Ok(()),
            )
            .await
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let mut tasks = Vec::new();
        for operation in ["client-a", "client-b"] {
            let authority = authority.clone();
            let barrier = barrier.clone();
            let provider = provider.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                authority
                    .apply_settled_advance(
                        ApplyOnboardingTransition {
                            run_id: provider.run_id,
                            attempt_id: provider.attempt_id,
                            expected_revision: provider.revision,
                            client_operation_id: operation.into(),
                            transition: OnboardingTransitionKind::Advance,
                            settlement: Some(cockpit_proto::OnboardingStageSettlement {
                                run_id: provider.run_id,
                                attempt_id: provider.attempt_id,
                                stage_revision: provider.revision,
                                settlement_operation_id: "provider-settled".into(),
                                provider_id: Some("provider".into()),
                                mutation_intent_hash: Some("aa".repeat(32)),
                                wizard_id: None,
                                config_generation: 1,
                            }),
                        },
                        capabilities(),
                    )
                    .await
            }));
        }
        barrier.wait().await;
        let first = tasks.remove(0).await.unwrap();
        let second = tasks.remove(0).await.unwrap();
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(
            authority
                .snapshot(capabilities())
                .await
                .unwrap()
                .unwrap()
                .stage,
            OnboardingStage::Model
        );
    }
}
