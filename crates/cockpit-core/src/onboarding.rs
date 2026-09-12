//! Daemon-owned onboarding transition authority.
//!
//! The authority is deliberately vault-free.  It persists only redacted state
//! and hands the one-shot passphrase to the daemon composition boundary; it
//! never writes configuration or credential files itself.

use anyhow::{Context, Result, bail};
use cockpit_proto::{
    ApplyOnboardingSecureIntent, BeginOrReopenOnboarding, HostCapabilitySnapshot,
    OnboardingBootstrapSnapshot, OnboardingBootstrapState, OnboardingReceiptStatus,
    OnboardingSecurePlacement, OnboardingStage, OnboardingTransitionReceipt,
};

use crate::db::onboarding::{
    OnboardingBootstrapState as DbBootstrapState, OnboardingReceiptRow,
    OnboardingReceiptStatus as DbReceiptStatus, OnboardingSnapshotRow,
    OnboardingStage as DbStage,
};
use crate::db::Db;

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
            .onboarding_begin_or_reopen(request.expected_revision, request.client_operation_id)
            .await?;
        let receipt = receipt(receipt);
        let snapshot = project(row, host_capabilities, Some(receipt.clone()))?;
        Ok((snapshot, receipt))
    }

    /// Record a secure-store selection before any vault-bearing service can be
    /// constructed.  The caller must materialize the selected vault through
    /// `SecureKeyActor` and then call `mark_secure_store_ready`; this split
    /// makes an interrupted passphrase operation resume as awaiting a new
    /// passphrase without persisting it.
    pub async fn accept_secure_intent(
        &self,
        request: ApplyOnboardingSecureIntent,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        let passphrase_present = request.passphrase.is_some();
        match request.placement {
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
        if current.run_id != request.run_id
            || current.attempt_id != request.attempt_id
            || current.revision != request.expected_revision
        {
            bail!("onboarding revision conflict");
        }
        let bootstrap_state = if matches!(request.placement, OnboardingSecurePlacement::PassphraseFile) {
            DbBootstrapState::AwaitingPassphrase
        } else {
            DbBootstrapState::Materializing
        };
        let (row, receipt_row) = self
            .db
            .onboarding_transition(
                current,
                request.client_operation_id,
                DbStage::SecureStore,
                bootstrap_state,
                false,
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
        let current = self.db.onboarding_snapshot().await?.context("no onboarding run exists")?;
        if current.run_id != expected.run_id
            || current.attempt_id != expected.attempt_id
            || current.revision != expected.revision
        {
            bail!("onboarding revision conflict");
        }
        let (row, receipt_row) = self
            .db
            .onboarding_transition(
                current,
                client_operation_id,
                DbStage::Provider,
                DbBootstrapState::Ready,
                false,
            )
            .await?;
        let receipt = receipt(receipt_row);
        let snapshot = project(row, host_capabilities, Some(receipt.clone()))?;
        Ok((snapshot, receipt))
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
