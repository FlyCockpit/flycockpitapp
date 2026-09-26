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
    OnboardingBootstrapState as DbBootstrapState, OnboardingOperationFingerprint,
    OnboardingReceiptRow, OnboardingReceiptStatus as DbReceiptStatus, OnboardingSnapshotRow,
    OnboardingStage as DbStage,
};

/// Typed rejection raised by the secure-intent authority before any vault
/// materialization. Boundaries classify it with `anyhow::Error::downcast_ref`
/// (together with `cockpit_db::onboarding::OnboardingRevisionConflict` and
/// `SecureKeyError`); they never match message text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecureIntentRejection {
    #[error("secure-store choice is already committed")]
    AlreadyCommitted,
    #[error("passphrase placement requires a confirmed passphrase")]
    PassphraseRequired,
    #[error("passphrase is only valid for passphrase placement")]
    PassphraseNotAllowed,
    #[error("no onboarding run exists")]
    NoActiveRun,
    #[error("secure-store intent is only valid at the secure-store stage")]
    WrongStage,
    #[error("secure-store capability has not been published")]
    CapabilityUnpublished,
    #[error("selected secure-store placement is unavailable: {guidance}")]
    CapabilityUnavailable { guidance: String },
    /// The client operation id is empty, too long, or in the reserved
    /// internal namespace.
    #[error("{0}")]
    InvalidOperationId(String),
    /// This exact operation was already decided and rejected.
    #[error("this secure-store operation was rejected")]
    PriorOperationRejected,
    /// This exact operation's effect is uncertain and no vault exists.
    #[error("this secure-store operation did not complete")]
    PriorOperationUncertain,
}

/// Classify a secure-intent failure into the fixed wire rejection by type.
///
/// The full error is logged by the caller; only a fixed reason code crosses
/// the preparation-time boundary.
pub fn classify_secure_intent_error(
    error: &anyhow::Error,
) -> cockpit_proto::SensitiveOnboardingIntentError {
    use cockpit_proto::SecurePlacementFailureReason as Reason;
    use cockpit_proto::SensitiveOnboardingIntentError as Wire;

    if error
        .downcast_ref::<crate::db::onboarding::OnboardingRevisionConflict>()
        .is_some()
        // An operation id reused with other parameters (or another
        // passphrase) is a conflict with the recorded operation.
        || error
            .downcast_ref::<crate::db::onboarding::OnboardingOperationReused>()
            .is_some()
    {
        return Wire::RevisionConflict;
    }
    if let Some(rejection) = error.downcast_ref::<SecureIntentRejection>() {
        return match rejection {
            SecureIntentRejection::AlreadyCommitted
            | SecureIntentRejection::PassphraseRequired
            | SecureIntentRejection::PassphraseNotAllowed
            | SecureIntentRejection::NoActiveRun
            | SecureIntentRejection::WrongStage
            | SecureIntentRejection::InvalidOperationId(_)
            | SecureIntentRejection::PriorOperationRejected => Wire::InvalidRequest,
            SecureIntentRejection::PriorOperationUncertain => {
                Wire::MaterializationFailed(Reason::Unclassified)
            }
            SecureIntentRejection::CapabilityUnpublished
            | SecureIntentRejection::CapabilityUnavailable { .. } => {
                Wire::PlacementUnavailable(Reason::CapabilityUnavailable)
            }
        };
    }
    if let Some(secure_key) = error.downcast_ref::<crate::secure_key::SecureKeyError>() {
        use crate::secure_key::KekFailureCause as Cause;
        return match Cause::of(secure_key) {
            Cause::KeyringUnavailable => Wire::PlacementUnavailable(Reason::KeyringUnavailable),
            Cause::KeyringLocked => Wire::PlacementUnavailable(Reason::KeyringLocked),
            Cause::KeyringDenied => Wire::PlacementUnavailable(Reason::KeyringAccessDenied),
            Cause::FileVaultUnsupported => Wire::PlacementUnavailable(Reason::FileVaultUnsupported),
            Cause::InvalidRequest => Wire::InvalidRequest,
            Cause::VaultStorage => Wire::MaterializationFailed(Reason::VaultStorageInaccessible),
            Cause::Passphrase => Wire::MaterializationFailed(Reason::PassphraseRejected),
            Cause::LocalState => Wire::MaterializationFailed(Reason::LocalStateUnavailable),
            Cause::Corrupt => Wire::MaterializationFailed(Reason::VaultCorrupt),
            Cause::Internal => Wire::MaterializationFailed(Reason::Unclassified),
        };
    }
    Wire::MaterializationFailed(Reason::Unclassified)
}

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

/// Prefix of daemon-derived onboarding operation ids. Client operation ids
/// may never use it, so an internal operation (a secure-store stage advance,
/// a boot reconciliation) can never collide with, or be pre-empted by, a
/// client's receipt.
const INTERNAL_OPERATION_ID_PREFIX: &str = "cockpit-internal:";

/// The single validator for client-supplied onboarding operation ids, run
/// before any durable or irreversible effect.
fn validate_client_operation_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 128 {
        bail!("onboarding client operation id must be 1 to 128 bytes");
    }
    if id.starts_with(INTERNAL_OPERATION_ID_PREFIX) {
        bail!("onboarding client operation id uses the reserved internal namespace");
    }
    Ok(())
}

/// A daemon-derived operation id. Fixed-width (a UUID or revision after the
/// reserved prefix), so it always fits the receipt key whatever the client
/// id length was.
fn internal_operation_id(kind: &str, discriminator: impl std::fmt::Display) -> String {
    format!("{INTERNAL_OPERATION_ID_PREFIX}{kind}:{discriminator}")
}

/// A secure-store intent after ingress: its validated identity, including a
/// slow, salted binding of the passphrase value (see
/// [`crate::secure_key::onboarding_passphrase_binding`]), and its one-shot
/// passphrase. The identity is what a receipt replays against; the
/// passphrase is consumed by materialization and never retained.
pub struct SecureIntentSubmission {
    run_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    expected_revision: u64,
    client_operation_id: String,
    placement: OnboardingSecurePlacement,
    passphrase: Option<Zeroizing<String>>,
    fingerprint: OnboardingOperationFingerprint,
}

/// The secret-free lookup identity of a [`SecureIntentSubmission`]: what its
/// receipt is keyed and fingerprinted by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureIntentKey {
    run_id: uuid::Uuid,
    attempt_id: uuid::Uuid,
    client_operation_id: String,
    fingerprint: OnboardingOperationFingerprint,
}

impl SecureIntentSubmission {
    pub fn key(&self) -> SecureIntentKey {
        SecureIntentKey {
            run_id: self.run_id,
            attempt_id: self.attempt_id,
            client_operation_id: self.client_operation_id.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

impl std::fmt::Debug for SecureIntentSubmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecureIntentSubmission")
            .field("run_id", &self.run_id)
            .field("attempt_id", &self.attempt_id)
            .field("expected_revision", &self.expected_revision)
            .field("client_operation_id", &self.client_operation_id)
            .field("placement", &self.placement)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// The canonical request identity of a client transition: kind, expected
/// revision, and settlement correlation. It determines the outcome at that
/// revision, so its receipt can answer a lost-acknowledgement retry after
/// the checkpoint moved on.
fn client_transition_fingerprint(
    request: &ApplyOnboardingTransition,
) -> Result<OnboardingOperationFingerprint> {
    let canonical = format!(
        "{}:{}:{}",
        serde_json::to_string(&request.transition).context("encoding onboarding transition")?,
        request.expected_revision,
        serde_json::to_string(&request.settlement).context("encoding onboarding settlement")?,
    );
    Ok(OnboardingOperationFingerprint::client_transition(
        &canonical,
    ))
}

#[derive(Clone)]
pub struct OnboardingAuthority {
    db: Db,
    /// Test seam: fail the next secure intent's bookkeeping right after its
    /// vault committed (receipt settlement), taking the production error path.
    #[cfg(test)]
    fail_next_post_commit: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl OnboardingAuthority {
    pub fn new(db: Db) -> Self {
        Self {
            db,
            #[cfg(test)]
            fail_next_post_commit: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    #[cfg(all(test, unix))]
    pub(crate) fn inject_post_commit_failure(&self) {
        self.fail_next_post_commit
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether a durable vault authority row exists: the commit point of a
    /// secure-store materialization.
    fn durable_vault_exists(&self) -> Result<bool> {
        self.db
            .blocking_write_for_sync_maintenance(cockpit_db::secret_vault::load_authority_conn)
            .map(|authority| authority.is_some())
    }

    /// Validate a secure-store intent and derive its operation identity
    /// before any lookup or effect.
    pub async fn prepare_secure_intent(
        &self,
        request: ApplyOnboardingSecureIntent,
    ) -> Result<SecureIntentSubmission> {
        validate_client_operation_id(&request.client_operation_id)
            .map_err(|error| SecureIntentRejection::InvalidOperationId(error.to_string()))?;
        let passphrase = request.passphrase.map(|value| value.into_zeroizing());
        let binding = match passphrase.as_ref() {
            None => None,
            Some(value) => {
                let bytes = Zeroizing::new(value.as_bytes().to_vec());
                let context = format!(
                    "{}:{}:{}",
                    request.run_id, request.attempt_id, request.client_operation_id
                )
                .into_bytes();
                Some(
                    tokio::task::spawn_blocking(move || {
                        crate::secure_key::onboarding_passphrase_binding(&bytes, &context)
                    })
                    .await
                    .context("onboarding passphrase binding task failed")?
                    .map_err(anyhow::Error::new)?,
                )
            }
        };
        let fingerprint = OnboardingOperationFingerprint::secure_store(
            db_placement(request.placement),
            binding.as_deref(),
        );
        Ok(SecureIntentSubmission {
            run_id: request.run_id,
            attempt_id: request.attempt_id,
            expected_revision: request.expected_revision,
            client_operation_id: request.client_operation_id,
            placement: request.placement,
            passphrase,
            fingerprint,
        })
    }

    /// The receipt of exactly this submission (any status) with the current
    /// snapshot. An operation id reused for a different request is
    /// [`crate::db::onboarding::OnboardingOperationReused`].
    pub async fn secure_intent_receipt(
        &self,
        key: &SecureIntentKey,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<Option<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)>> {
        let Some((row, receipt_row)) = self
            .db
            .onboarding_receipt_with_fingerprint(
                key.run_id,
                key.attempt_id,
                key.client_operation_id.clone(),
                key.fingerprint.clone(),
            )
            .await?
        else {
            return Ok(None);
        };
        let receipt = receipt(receipt_row);
        Ok(Some((
            project(row, host_capabilities, Some(receipt.clone()))?,
            receipt,
        )))
    }

    /// The receipt of exactly this client transition request, if it already
    /// committed: the answer to a retried request whose acknowledgement was
    /// lost. Checked before any revision comparison.
    pub async fn transition_replay(
        &self,
        request: &ApplyOnboardingTransition,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<Option<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)>> {
        validate_client_operation_id(&request.client_operation_id)?;
        let Some((row, receipt_row)) = self
            .db
            .onboarding_receipt_with_fingerprint(
                request.run_id,
                request.attempt_id,
                request.client_operation_id.clone(),
                client_transition_fingerprint(request)?,
            )
            .await?
        else {
            return Ok(None);
        };
        let receipt = receipt(receipt_row);
        Ok(Some((
            project(row, host_capabilities, Some(receipt.clone()))?,
            receipt,
        )))
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
        validate_client_operation_id(&request.client_operation_id)?;
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

    /// Idempotent replay of an already committed secure-store intent. Once
    /// the vault authority exists a fresh materialization is impossible, but
    /// the same submission (same run, attempt, and client operation id) may
    /// legitimately arrive again after its response was lost. It resolves to
    /// the committed receipt and the current snapshot instead of an opaque
    /// rejection. Anything else (another operation id, an uncommitted
    /// receipt) returns `None` and the caller keeps its fail-closed denial.
    pub async fn committed_secure_intent_replay(
        &self,
        key: &SecureIntentKey,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<Option<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)>> {
        // Only the exact secure-store operation replays: the receipt must be
        // of the `secure_store` kind with this request's fingerprint (which
        // binds the passphrase value). A receipt of another operation sharing
        // the id is not evidence that this intent committed.
        let Some((_, committed)) = self
            .secure_intent_receipt(key, host_capabilities.clone())
            .await?
        else {
            return Ok(None);
        };
        if committed.status != OnboardingReceiptStatus::Committed {
            return Ok(None);
        }
        let Some(snapshot) = self.snapshot(host_capabilities).await? else {
            return Ok(None);
        };
        Ok(Some((snapshot, committed)))
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
        let submission = self.prepare_secure_intent(request).await?;
        self.apply_prepared_secure_intent_with(
            submission,
            host_capabilities,
            vault_authority_exists,
            materialize,
        )
        .await
    }

    /// [`Self::apply_secure_intent_with`] for an already prepared submission.
    ///
    /// A prior receipt of this exact submission answers only by its own
    /// status: `Committed` is the applied result; `Rejected`, `Unknown`, or a
    /// still-`Pending` receipt is never reported as success. After the
    /// effect, the receipt settles from durable evidence: a materializer
    /// error with a vault authority present still committed the choice.
    pub async fn apply_prepared_secure_intent_with<F>(
        &self,
        mut submission: SecureIntentSubmission,
        host_capabilities: HostCapabilitySnapshot,
        vault_authority_exists: bool,
        materialize: F,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)>
    where
        F: FnOnce(OnboardingSecurePlacement, Option<Zeroizing<String>>) -> Result<()>,
    {
        if let Some((snapshot, prior)) = self
            .secure_intent_receipt(&submission.key(), host_capabilities.clone())
            .await?
        {
            return match prior.status {
                OnboardingReceiptStatus::Committed => Ok((snapshot, prior)),
                OnboardingReceiptStatus::Rejected => {
                    Err(SecureIntentRejection::PriorOperationRejected.into())
                }
                OnboardingReceiptStatus::Unknown | OnboardingReceiptStatus::Pending => {
                    Err(SecureIntentRejection::PriorOperationUncertain.into())
                }
            };
        }
        if vault_authority_exists {
            return Err(SecureIntentRejection::AlreadyCommitted.into());
        }
        let placement = submission.placement;
        let passphrase = submission.passphrase.take();
        let (pending, pending_receipt) = self
            .record_secure_intent(&submission, passphrase.is_some(), host_capabilities.clone())
            .await?;
        if let Err(error) = materialize(placement, passphrase) {
            // The authority row is the commit point. Settle from it now when
            // it can be read: absent means no effect (rejected), present
            // means the choice committed despite the later error. Only an
            // unreadable authority leaves the effect uncertain for
            // reconciliation.
            match self.durable_vault_exists() {
                Ok(false) => {
                    self.db
                        .onboarding_settle_uncertain_receipt(
                            pending_receipt.receipt_id,
                            DbReceiptStatus::Rejected,
                        )
                        .await
                        .context("recording a failed secure-store materialization")?;
                    return Err(error);
                }
                Ok(true) => {
                    tracing::warn!(
                        error = %format!("{error:#}"),
                        "secure-store materialization reported an error after its vault authority committed; settling the choice as committed"
                    );
                }
                Err(evidence) => {
                    tracing::warn!(
                        error = %format!("{evidence:#}"),
                        "vault authority unreadable after a failed materialization; the outcome stays uncertain"
                    );
                    self.db
                        .onboarding_set_pending_receipt_status(
                            pending_receipt.receipt_id,
                            DbReceiptStatus::Unknown,
                        )
                        .await
                        .context("recording uncertain secure-store materialization")?;
                    return Err(error);
                }
            }
        }
        #[cfg(test)]
        if self
            .fail_next_post_commit
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            bail!("injected failure settling the committed secure-store receipt");
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
                internal_operation_id("secure-store-ready", pending_receipt.receipt_id),
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
        submission: &SecureIntentSubmission,
        passphrase_present: bool,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        let run_id = submission.run_id;
        let attempt_id = submission.attempt_id;
        let expected_revision = submission.expected_revision;
        let placement = submission.placement;
        match placement {
            OnboardingSecurePlacement::PassphraseFile if !passphrase_present => {
                return Err(SecureIntentRejection::PassphraseRequired.into());
            }
            OnboardingSecurePlacement::PassphraseFile => {}
            _ if passphrase_present => {
                return Err(SecureIntentRejection::PassphraseNotAllowed.into());
            }
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
            .ok_or(SecureIntentRejection::CapabilityUnpublished)?;
        if !capability.state.is_available() {
            let guidance = capability
                .fix_command
                .as_deref()
                .or(capability.remedy_text.as_deref())
                .unwrap_or(capability.reason.as_str());
            return Err(SecureIntentRejection::CapabilityUnavailable {
                guidance: guidance.to_string(),
            }
            .into());
        }
        let current = self
            .db
            .onboarding_snapshot()
            .await?
            .ok_or(SecureIntentRejection::NoActiveRun)?;
        if current.run_id != run_id
            || current.attempt_id != attempt_id
            || current.revision != expected_revision
        {
            return Err(crate::db::onboarding::OnboardingRevisionConflict.into());
        }
        if current.stage != DbStage::SecureStore {
            return Err(SecureIntentRejection::WrongStage.into());
        }
        let (row, receipt_row) = self
            .db
            .onboarding_secure_intent_pending(
                current,
                submission.client_operation_id.clone(),
                db_placement(placement),
                submission.fingerprint.clone(),
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
        // Every unsettled (`pending` or `unknown`) secure-store receipt is
        // terminalized from the durable evidence first, at every crash
        // boundary. Effects are serialized and a committed vault refuses
        // every later intent, so only the latest unsettled operation can be
        // the one that committed: it settles committed when the vault proves
        // the effect and rejected otherwise; any earlier one did not commit.
        // Idempotent under concurrent reconcilers (boot, construction).
        let uncertain = self
            .db
            .onboarding_uncertain_secure_intent_receipts()
            .await?;
        let latest = uncertain.last().map(|receipt| receipt.receipt_id);
        for receipt in &uncertain {
            let status = if vault_authority_exists && Some(receipt.receipt_id) == latest {
                DbReceiptStatus::Committed
            } else {
                DbReceiptStatus::Rejected
            };
            self.db
                .onboarding_settle_uncertain_receipt(receipt.receipt_id, status)
                .await
                .context("terminalizing an interrupted secure-store receipt")?;
        }
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
        let operation_id = internal_operation_id("bootstrap-reconcile", current.revision);
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
        validate_client_operation_id(&request.client_operation_id)?;
        if request.settlement.is_some() {
            bail!("settlement correlation is only valid for provider, model, or agent advance");
        }
        if let Some(replayed) = self
            .transition_replay(&request, host_capabilities.clone())
            .await?
        {
            return Ok(replayed);
        }
        let fingerprint = client_transition_fingerprint(&request)?;
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
            fingerprint,
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
        validate_client_operation_id(&request.client_operation_id)?;
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
        if let Some(replayed) = self
            .transition_replay(&request, host_capabilities.clone())
            .await?
        {
            return Ok(replayed);
        }
        let fingerprint = client_transition_fingerprint(&request)?;
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
            fingerprint,
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
        fingerprint: OnboardingOperationFingerprint,
        stage: DbStage,
        limited_mode: bool,
        host_capabilities: HostCapabilitySnapshot,
    ) -> Result<(OnboardingBootstrapSnapshot, OnboardingTransitionReceipt)> {
        let selected_secure_placement = current.selected_secure_placement;
        let (row, receipt_row) = self
            .db
            .onboarding_client_transition(
                current,
                client_operation_id,
                fingerprint,
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

    fn machine_bound_intent(
        secure: &OnboardingBootstrapSnapshot,
        client_operation_id: &str,
    ) -> ApplyOnboardingSecureIntent {
        ApplyOnboardingSecureIntent {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: client_operation_id.into(),
            placement: OnboardingSecurePlacement::MachineBoundFile,
            passphrase: None,
        }
    }

    /// The crash boundaries of one secure-store intent, simulated on the
    /// durable rows: after the pending receipt, after the vault commit (the
    /// receipt still pending), after the receipt commit (the stage not yet
    /// advanced), and after the stage advance. Boot reconciliation must
    /// terminalize the ORIGINAL operation's receipt from the vault evidence at
    /// every one of them, so the original client operation replays.
    #[derive(Clone, Copy, Debug)]
    enum CrashBoundary {
        PendingReceiptNoVault,
        VaultCommittedReceiptPending,
        ReceiptCommittedStageNotAdvanced,
        StageAdvanced,
    }

    async fn crash_at(
        boundary: CrashBoundary,
    ) -> (OnboardingAuthority, OnboardingBootstrapSnapshot) {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db);
        let secure = secure_stage(&authority).await;
        let submission = authority
            .prepare_secure_intent(machine_bound_intent(&secure, "crash-intent"))
            .await
            .unwrap();
        let (pending, pending_receipt) = authority
            .record_secure_intent(&submission, false, capabilities())
            .await
            .unwrap();
        match boundary {
            CrashBoundary::PendingReceiptNoVault | CrashBoundary::VaultCommittedReceiptPending => {}
            CrashBoundary::ReceiptCommittedStageNotAdvanced => {
                authority
                    .db
                    .onboarding_set_pending_receipt_status(
                        pending_receipt.receipt_id,
                        DbReceiptStatus::Committed,
                    )
                    .await
                    .unwrap();
            }
            CrashBoundary::StageAdvanced => {
                authority
                    .db
                    .onboarding_set_pending_receipt_status(
                        pending_receipt.receipt_id,
                        DbReceiptStatus::Committed,
                    )
                    .await
                    .unwrap();
                authority
                    .mark_secure_store_ready(
                        &pending,
                        internal_operation_id("secure-store-ready", pending_receipt.receipt_id),
                        capabilities(),
                    )
                    .await
                    .unwrap();
            }
        }
        (authority, secure)
    }

    #[tokio::test]
    async fn boot_reconciliation_terminalizes_the_original_receipt_at_every_crash_boundary() {
        for boundary in [
            CrashBoundary::PendingReceiptNoVault,
            CrashBoundary::VaultCommittedReceiptPending,
            CrashBoundary::ReceiptCommittedStageNotAdvanced,
            CrashBoundary::StageAdvanced,
        ] {
            let (authority, secure) = crash_at(boundary).await;
            let vault_exists = !matches!(boundary, CrashBoundary::PendingReceiptNoVault);
            let reconciled = authority
                .reconcile_materializing_secure_intent(vault_exists, capabilities())
                .await
                .unwrap()
                .expect("run exists");
            let original = authority
                .receipt(cockpit_proto::OnboardingReceiptQuery {
                    run_id: secure.run_id,
                    attempt_id: secure.attempt_id,
                    client_operation_id: "crash-intent".into(),
                })
                .await
                .unwrap()
                .expect("the original receipt exists");
            let key = authority
                .prepare_secure_intent(machine_bound_intent(&secure, "crash-intent"))
                .await
                .unwrap()
                .key();
            let replay = authority
                .committed_secure_intent_replay(&key, capabilities())
                .await
                .unwrap();
            if vault_exists {
                assert_eq!(
                    original.status,
                    OnboardingReceiptStatus::Committed,
                    "{boundary:?}: the vault proves the original effect"
                );
                assert_eq!(reconciled.stage, OnboardingStage::Provider, "{boundary:?}");
                assert_eq!(reconciled.bootstrap_state, OnboardingBootstrapState::Ready);
                assert!(
                    replay.is_some(),
                    "{boundary:?}: the original operation replays"
                );
            } else {
                assert_eq!(
                    original.status,
                    OnboardingReceiptStatus::Rejected,
                    "{boundary:?}: no vault, no effect"
                );
                assert_eq!(reconciled.stage, OnboardingStage::SecureStore);
                assert!(replay.is_none());
            }
            // Idempotent: a second boot changes nothing.
            let again = authority
                .reconcile_materializing_secure_intent(vault_exists, capabilities())
                .await
                .unwrap()
                .expect("run exists");
            assert_eq!(again.revision, reconciled.revision, "{boundary:?}");
        }
    }

    fn passphrase_intent(
        secure: &OnboardingBootstrapSnapshot,
        client_operation_id: &str,
        passphrase: &str,
    ) -> ApplyOnboardingSecureIntent {
        ApplyOnboardingSecureIntent {
            run_id: secure.run_id,
            attempt_id: secure.attempt_id,
            expected_revision: secure.revision,
            client_operation_id: client_operation_id.into(),
            placement: OnboardingSecurePlacement::PassphraseFile,
            passphrase: Some(
                SensitiveOnboardingPassphrase::confirmed(passphrase.into(), passphrase.into())
                    .unwrap(),
            ),
        }
    }

    /// G8: the secure-store fingerprint binds the passphrase value. The same
    /// operation id with the same passphrase replays; with a different
    /// passphrase it is a conflict, never an `Applied` for a secret that was
    /// not the one committed. The value itself is never stored.
    #[tokio::test]
    async fn secure_intent_replay_binds_the_passphrase_value() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db.clone());
        let secure = secure_stage(&authority).await;
        let (_, committed) = authority
            .apply_secure_intent_with(
                passphrase_intent(&secure, "bound-intent", "first-passphrase"),
                capabilities(),
                false,
                |_, _| Ok(()),
            )
            .await
            .unwrap();
        let same = authority
            .prepare_secure_intent(passphrase_intent(
                &secure,
                "bound-intent",
                "first-passphrase",
            ))
            .await
            .unwrap();
        let replay = authority
            .committed_secure_intent_replay(&same.key(), capabilities())
            .await
            .unwrap()
            .expect("the same passphrase replays");
        assert_eq!(replay.1.receipt_id, committed.receipt_id);
        let other = authority
            .prepare_secure_intent(passphrase_intent(
                &secure,
                "bound-intent",
                "second-passphrase",
            ))
            .await
            .unwrap();
        let error = authority
            .committed_secure_intent_replay(&other.key(), capabilities())
            .await
            .expect_err("another passphrase under the same id is a conflict");
        assert_eq!(
            classify_secure_intent_error(&error),
            cockpit_proto::SensitiveOnboardingIntentError::RevisionConflict
        );
        let stored = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT group_concat(operation_digest, '|') FROM onboarding_receipts",
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )?)
            })
            .await
            .unwrap()
            .unwrap_or_default();
        assert!(!stored.contains("first-passphrase"));
    }

    /// F6/G2: a materializer error after the vault authority committed is a
    /// committed choice (the authority row is the commit point), and boot
    /// reconciliation settles `unknown` receipts from the vault evidence:
    /// the latest unsettled operation is the one that committed, earlier
    /// ones did not.
    #[tokio::test]
    async fn uncertain_secure_intents_settle_from_the_vault_authority() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db.clone());
        let secure = secure_stage(&authority).await;
        let writer = db.clone();
        let (committed_snapshot, committed) = authority
            .apply_secure_intent_with(
                machine_bound_intent(&secure, "commit-then-fail"),
                capabilities(),
                false,
                move |_, _| {
                    writer.blocking_write_for_sync_maintenance(|conn| {
                        conn.execute(
                            "INSERT INTO secret_vault_authority VALUES (1, 'database', 'database', 'machine_bound', 'test-fingerprint', 1, 1, 0)",
                            [],
                        )?;
                        Ok(())
                    })?;
                    anyhow::bail!("opening the committed vault failed")
                },
            )
            .await
            .expect("a committed authority settles the choice as committed");
        assert_eq!(committed.status, OnboardingReceiptStatus::Committed);
        assert_eq!(committed_snapshot.stage, OnboardingStage::Provider);

        // Boot reconciliation over two unsettled receipts: an earlier one and
        // the latest, both left `unknown` by crashes before settlement.
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db.clone());
        let secure = secure_stage(&authority).await;
        let earlier = authority
            .prepare_secure_intent(machine_bound_intent(&secure, "earlier"))
            .await
            .unwrap();
        let (after_earlier, earlier_receipt) = authority
            .record_secure_intent(&earlier, false, capabilities())
            .await
            .unwrap();
        db.onboarding_set_pending_receipt_status(
            earlier_receipt.receipt_id,
            DbReceiptStatus::Unknown,
        )
        .await
        .unwrap();
        let latest = authority
            .prepare_secure_intent(machine_bound_intent(&after_earlier, "latest"))
            .await
            .unwrap();
        let (_, latest_receipt) = authority
            .record_secure_intent(&latest, false, capabilities())
            .await
            .unwrap();
        db.onboarding_set_pending_receipt_status(
            latest_receipt.receipt_id,
            DbReceiptStatus::Unknown,
        )
        .await
        .unwrap();
        let reconciled = authority
            .reconcile_materializing_secure_intent(true, capabilities())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reconciled.stage, OnboardingStage::Provider);
        let status = |id: &str| {
            let authority = authority.clone();
            let query = cockpit_proto::OnboardingReceiptQuery {
                run_id: secure.run_id,
                attempt_id: secure.attempt_id,
                client_operation_id: id.into(),
            };
            async move { authority.receipt(query).await.unwrap().unwrap().status }
        };
        assert_eq!(status("latest").await, OnboardingReceiptStatus::Committed);
        assert_eq!(status("earlier").await, OnboardingReceiptStatus::Rejected);
        // Idempotent under a concurrent or repeated reconciler.
        authority
            .reconcile_materializing_secure_intent(true, capabilities())
            .await
            .unwrap();
        assert_eq!(status("latest").await, OnboardingReceiptStatus::Committed);
    }

    /// G9: a client transition whose acknowledgement was lost is re-sent
    /// unchanged after the checkpoint moved on; it answers from its receipt
    /// (same receipt, no second revision) instead of a revision conflict.
    /// The same id with a different request is a conflict.
    #[tokio::test]
    async fn lost_ack_transition_retry_returns_the_original_result() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db);
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
        let request = ApplyOnboardingTransition {
            run_id: welcome.run_id,
            attempt_id: welcome.attempt_id,
            expected_revision: welcome.revision,
            client_operation_id: "advance-welcome".into(),
            transition: OnboardingTransitionKind::Advance,
            settlement: None,
        };
        let (first, first_receipt) = authority
            .apply_transition(request.clone(), capabilities())
            .await
            .unwrap();
        let (retried, retried_receipt) = authority
            .apply_transition(request.clone(), capabilities())
            .await
            .expect("the lost-ack retry answers from its receipt");
        assert_eq!(retried_receipt.receipt_id, first_receipt.receipt_id);
        assert_eq!(retried.revision, first.revision, "no second revision");
        let replay = authority
            .transition_replay(&request, capabilities())
            .await
            .unwrap()
            .expect("the receipt answers before any revision check");
        assert_eq!(replay.1.receipt_id, first_receipt.receipt_id);
        let reused = authority
            .apply_transition(
                ApplyOnboardingTransition {
                    transition: OnboardingTransitionKind::Back,
                    ..request
                },
                capabilities(),
            )
            .await
            .expect_err("the same id for a different request is a conflict");
        assert!(
            reused
                .downcast_ref::<crate::db::onboarding::OnboardingOperationReused>()
                .is_some(),
            "{reused:#}"
        );
    }

    #[tokio::test]
    async fn reserved_internal_operation_ids_are_rejected_before_any_effect() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db);
        let secure = secure_stage(&authority).await;
        let materialized = Arc::new(AtomicUsize::new(0));
        let calls = materialized.clone();
        let error = authority
            .apply_secure_intent_with(
                machine_bound_intent(&secure, "cockpit-internal:secure-store-ready:x"),
                capabilities(),
                false,
                move |_, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .await
            .expect_err("reserved namespace");
        assert!(error.to_string().contains("reserved"), "{error:#}");
        assert_eq!(materialized.load(Ordering::SeqCst), 0);
        let too_long = authority
            .apply_secure_intent_with(
                machine_bound_intent(&secure, &"y".repeat(129)),
                capabilities(),
                false,
                |_, _| panic!("an over-long id must be rejected before materialization"),
            )
            .await;
        assert!(too_long.is_err());
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
            .expect_err("failed materialization must leave a materializing checkpoint");
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
        // No vault authority exists after the failure, and the authority row
        // is the commit point: the operation definitively did not commit.
        assert_eq!(uncertain.status, OnboardingReceiptStatus::Rejected);
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

    #[test]
    fn secure_intent_errors_are_classified_by_type_not_message_text() {
        use crate::secure_key::{KekFailureCause, SecureKeyError};
        use cockpit_proto::SecurePlacementFailureReason as Reason;
        use cockpit_proto::SensitiveOnboardingIntentError as Wire;

        // Every KEK failure's text says "KEK unavailable"; only its typed
        // cause may decide the class (the macOS onboarding misreport).
        let kek = |cause| {
            anyhow::Error::from(SecureKeyError::KekUnavailable {
                cause,
                reason: "unavailable revision conflict requires already committed".into(),
                fix_command: None,
            })
            .context("materializing onboarding vault")
        };
        for (cause, expected) in [
            (
                KekFailureCause::KeyringUnavailable,
                Wire::PlacementUnavailable(Reason::KeyringUnavailable),
            ),
            (
                KekFailureCause::KeyringLocked,
                Wire::PlacementUnavailable(Reason::KeyringLocked),
            ),
            (
                KekFailureCause::KeyringDenied,
                Wire::PlacementUnavailable(Reason::KeyringAccessDenied),
            ),
            (
                KekFailureCause::FileVaultUnsupported,
                Wire::PlacementUnavailable(Reason::FileVaultUnsupported),
            ),
            (
                KekFailureCause::VaultStorage,
                Wire::MaterializationFailed(Reason::VaultStorageInaccessible),
            ),
            (
                KekFailureCause::Passphrase,
                Wire::MaterializationFailed(Reason::PassphraseRejected),
            ),
            (
                KekFailureCause::LocalState,
                Wire::MaterializationFailed(Reason::LocalStateUnavailable),
            ),
            (
                KekFailureCause::Corrupt,
                Wire::MaterializationFailed(Reason::VaultCorrupt),
            ),
            (
                KekFailureCause::Internal,
                Wire::MaterializationFailed(Reason::Unclassified),
            ),
            (KekFailureCause::InvalidRequest, Wire::InvalidRequest),
        ] {
            assert_eq!(
                classify_secure_intent_error(&kek(cause)),
                expected,
                "{cause:?}"
            );
        }

        // Raw keyring adapter errors classify without a KEK wrapper.
        assert_eq!(
            classify_secure_intent_error(&anyhow::Error::from(SecureKeyError::Locked(
                "keychain".into()
            ))),
            Wire::PlacementUnavailable(Reason::KeyringLocked)
        );
        assert_eq!(
            classify_secure_intent_error(
                &anyhow::Error::from(crate::db::onboarding::OnboardingRevisionConflict)
                    .context("recording secure intent")
            ),
            Wire::RevisionConflict
        );
        assert_eq!(
            classify_secure_intent_error(&SecureIntentRejection::AlreadyCommitted.into()),
            Wire::InvalidRequest
        );
        assert_eq!(
            classify_secure_intent_error(&SecureIntentRejection::WrongStage.into()),
            Wire::InvalidRequest
        );
        // Untyped text never classifies, whatever words it contains.
        assert_eq!(
            classify_secure_intent_error(&anyhow::anyhow!(
                "store unavailable: revision conflict requires only valid already committed"
            )),
            Wire::MaterializationFailed(Reason::Unclassified)
        );
    }

    #[tokio::test]
    async fn materializer_keyring_failure_reaches_the_wire_as_its_typed_reason() {
        let db = Db::open_in_memory_async().await.unwrap();
        let authority = OnboardingAuthority::new(db);
        let secure = secure_stage(&authority).await;
        let error = authority
            .apply_secure_intent_with(
                ApplyOnboardingSecureIntent {
                    run_id: secure.run_id,
                    attempt_id: secure.attempt_id,
                    expected_revision: secure.revision,
                    client_operation_id: "locked-keyring".into(),
                    placement: OnboardingSecurePlacement::Keyring,
                    passphrase: None,
                },
                capabilities(),
                false,
                |_, _| {
                    Err(crate::secure_key::SecureKeyError::Denied("keychain refused".into()).into())
                },
            )
            .await
            .expect_err("a refused keyring write must reject the secure intent");
        assert_eq!(
            classify_secure_intent_error(&error),
            cockpit_proto::SensitiveOnboardingIntentError::PlacementUnavailable(
                cockpit_proto::SecurePlacementFailureReason::KeyringAccessDenied,
            )
        );

        let stale = authority
            .apply_secure_intent_with(
                ApplyOnboardingSecureIntent {
                    run_id: secure.run_id,
                    attempt_id: secure.attempt_id,
                    expected_revision: secure.revision,
                    client_operation_id: "stale-revision".into(),
                    placement: OnboardingSecurePlacement::MachineBoundFile,
                    passphrase: None,
                },
                capabilities(),
                false,
                |_, _| Ok(()),
            )
            .await
            .expect_err("the consumed revision must conflict");
        assert_eq!(
            classify_secure_intent_error(&stale),
            cockpit_proto::SensitiveOnboardingIntentError::RevisionConflict
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
        assert_eq!(
            classify_secure_intent_error(&error),
            cockpit_proto::SensitiveOnboardingIntentError::PlacementUnavailable(
                cockpit_proto::SecurePlacementFailureReason::CapabilityUnavailable,
            )
        );
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
                                provider_mutation_config_generation: Some(1),
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
