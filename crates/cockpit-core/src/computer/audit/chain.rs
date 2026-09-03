//! Production tamper-evident computer-use audit-chain writer (issue #271).
//!
//! Root of trust:
//! - HMAC signing key in the existing protected secret store
//!   (`computer-audit/v1`)
//! - signed/checkpointed chain head in sealed state
//!   (`computer-audit-head/v1`)
//! - append-only SQLite bodies (`computer_audit_entries`)
//!
//! Verification fails closed on any break. There is no silent re-anchor.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use cockpit_db::computer_audit::{
    COMPUTER_AUDIT_ENTRY_LEN, ComputerAuditEntryRow, GUIDANCE_PROPOSAL_ACCEPTED,
    GUIDANCE_PROPOSAL_CREATED, GUIDANCE_PROPOSAL_EXPIRED, GUIDANCE_PROPOSAL_REJECTED,
};
use cockpit_db::installation_identity::InstallationIdentity;

use crate::db::Db;
use crate::secure_key::{
    COMPUTER_AUDIT_HEAD_V1_NAMESPACE, COMPUTER_AUDIT_V1_NAMESPACE, SealedPayload, SecureKeyBytes,
    SecureKeyError, SecureKeyHandle,
};

use super::{
    AuditEventKind, AuditVerifyResult, AuditVerifyStatus, ChainEntry, ComputerAuditEntryV1,
    ComputerAuditSealedHeadV1, Disposition, ENTRY_LEN, GuidanceScope, present_bits, verify_chain,
};

const MAX_CAS_RETRIES: usize = 8;

/// Fields for a guidance-proposal audit append. Typed rule values and
/// rationale never appear here.
#[derive(Debug, Clone)]
pub struct GuidanceAuditAppend {
    pub kind: AuditEventKind,
    pub proposal_id: [u8; 16],
    pub session_id: [u8; 16],
    pub delegation_id: [u8; 16],
    pub canonical_project_digest: [u8; 32],
    pub provider_digest: [u8; 32],
    pub model_digest: [u8; 32],
    pub config_generation: u64,
    pub rule_kind_bits: u16,
    pub disposition: Option<Disposition>,
    pub scope: Option<GuidanceScope>,
}

struct ChainInner {
    hmac_keys: HashMap<u32, SecureKeyBytes>,
    current_key_version: u32,
    database_instance_id: [u8; 16],
    last_monotonic: u64,
}

/// Tamper-evident, append-only computer-use audit chain.
pub struct ComputerAuditChain {
    db: Arc<Db>,
    keys: SecureKeyHandle,
    inner: tokio::sync::Mutex<Option<ChainInner>>,
    available: AtomicBool,
}

impl ComputerAuditChain {
    /// Open or fail closed. Production boot uses this: a corrupt or
    /// unverifiable chain stays installed but `is_available()` is false.
    pub async fn open(db: Arc<Db>, keys: SecureKeyHandle) -> Self {
        match Self::try_open(db.clone(), keys.clone()).await {
            Ok(chain) => chain,
            Err(error) => {
                tracing::error!(%error, "computer audit chain failed closed");
                Self::unavailable(db, keys)
            }
        }
    }

    /// Open and require a verified chain. Tests use this so a setup failure
    /// is not mistaken for a healthy writer.
    pub async fn try_open(db: Arc<Db>, keys: SecureKeyHandle) -> Result<Self> {
        let chain = Self {
            db,
            keys,
            inner: tokio::sync::Mutex::new(None),
            available: AtomicBool::new(false),
        };
        chain.bootstrap().await?;
        Ok(chain)
    }

    fn unavailable(db: Arc<Db>, keys: SecureKeyHandle) -> Self {
        Self {
            db,
            keys,
            inner: tokio::sync::Mutex::new(None),
            available: AtomicBool::new(false),
        }
    }

    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    /// Verify the durable log against the sealed head. Any break is a
    /// non-`Verified` status; this never re-anchors.
    pub async fn verify(&self) -> AuditVerifyResult {
        let guard = self.inner.lock().await;
        let Some(inner) = guard.as_ref() else {
            return empty_status(AuditVerifyStatus::UnavailableSecureStore);
        };
        match self.verify_loaded(inner).await {
            Ok(result) => result,
            Err(_) => empty_status(AuditVerifyStatus::UnavailableDatabase),
        }
    }

    /// Append one guidance-proposal event. Idempotent for
    /// `(event_kind, proposal_id)` so outbox replay cannot fork the chain.
    pub async fn append_guidance(&self, event: GuidanceAuditAppend) -> Result<()> {
        if !self.is_available() {
            bail!("computer audit chain is not available");
        }
        anyhow::ensure!(
            is_guidance_kind(event.kind),
            "audit chain guidance append requires a guidance-proposal event kind"
        );
        let mut guard = self.inner.lock().await;
        let inner = guard
            .as_mut()
            .ok_or_else(|| anyhow!("computer audit chain is not available"))?;
        match self.append_locked(inner, &event).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let broken = match self.verify_loaded(inner).await {
                    Ok(result) => !matches!(
                        result.status,
                        AuditVerifyStatus::Verified | AuditVerifyStatus::PendingRecovery
                    ),
                    Err(_) => true,
                };
                if broken {
                    self.available.store(false, Ordering::Release);
                }
                Err(error)
            }
        }
    }

    async fn bootstrap(&self) -> Result<()> {
        let identity = self
            .db
            .ensure_installation_identity()
            .await
            .context("loading installation identity for computer audit chain")?;
        let database_instance_id = identity_bytes(&identity)?;

        let (version, hmac_key) = self
            .keys
            .create_or_load(COMPUTER_AUDIT_V1_NAMESPACE)
            .await
            .context("loading computer audit HMAC key")?;
        let current_key_version = u32::try_from(version).context("audit HMAC key version")?;
        anyhow::ensure!(
            current_key_version >= 1,
            "audit HMAC key version must be >= 1"
        );

        let mut hmac_keys = HashMap::new();
        hmac_keys.insert(current_key_version, hmac_key);

        let initial = ComputerAuditSealedHeadV1::confirmed_only(
            1,
            0,
            [0u8; 32],
            current_key_version,
            database_instance_id,
        );
        let initial_payload = SealedPayload::new(initial.encode())
            .map_err(|e| anyhow!("computer audit sealed head payload: {e}"))?;
        let view = self
            .keys
            .sealed_create_or_load(COMPUTER_AUDIT_HEAD_V1_NAMESPACE, initial_payload)
            .await
            .context("loading computer audit sealed head")?;
        let head = decode_head(view.payload.as_slice())?;
        anyhow::ensure!(
            head.database_instance_id == database_instance_id,
            "computer audit sealed head is bound to a different database instance"
        );

        let rows = self.db.list_computer_audit_entries().await?;
        for row in &rows {
            self.ensure_key(&mut hmac_keys, row.key_version).await?;
        }

        let last_monotonic = max_monotonic(&rows);
        let mut inner = ChainInner {
            hmac_keys,
            current_key_version,
            database_instance_id,
            last_monotonic,
        };

        let status = verify_with(&inner, Some(&head), Some(&rows))?;
        match status.status {
            AuditVerifyStatus::Verified => {}
            AuditVerifyStatus::PendingRecovery => {
                self.recover_pending(&mut inner, &view, &head, &rows)
                    .await?;
                let rows = self.db.list_computer_audit_entries().await?;
                let head = decode_head(
                    self.keys
                        .sealed_load(COMPUTER_AUDIT_HEAD_V1_NAMESPACE)
                        .await
                        .context("reloading sealed head after pending recovery")?
                        .payload
                        .as_slice(),
                )?;
                let status = verify_with(&inner, Some(&head), Some(&rows))?;
                if status.status != AuditVerifyStatus::Verified {
                    bail!(
                        "computer audit chain failed closed after pending recovery: {}",
                        status.status.as_str()
                    );
                }
            }
            other => {
                bail!("computer audit chain failed closed: {}", other.as_str());
            }
        }

        *self.inner.lock().await = Some(inner);
        self.available.store(true, Ordering::Release);
        Ok(())
    }

    async fn append_locked(
        &self,
        inner: &mut ChainInner,
        event: &GuidanceAuditAppend,
    ) -> Result<()> {
        for _ in 0..MAX_CAS_RETRIES {
            let mut view = self
                .keys
                .sealed_load(COMPUTER_AUDIT_HEAD_V1_NAMESPACE)
                .await
                .context("loading computer audit sealed head")?;
            let mut head = decode_head(view.payload.as_slice())?;
            let mut rows = self.db.list_computer_audit_entries().await?;
            let status = verify_with(inner, Some(&head), Some(&rows))?;
            match status.status {
                AuditVerifyStatus::Verified => {}
                AuditVerifyStatus::PendingRecovery => {
                    self.recover_pending(inner, &view, &head, &rows).await?;
                    view = self
                        .keys
                        .sealed_load(COMPUTER_AUDIT_HEAD_V1_NAMESPACE)
                        .await
                        .context("reloading sealed head after pending recovery")?;
                    head = decode_head(view.payload.as_slice())?;
                    rows = self.db.list_computer_audit_entries().await?;
                    let status = verify_with(inner, Some(&head), Some(&rows))?;
                    if status.status != AuditVerifyStatus::Verified {
                        bail!(
                            "computer audit chain failed closed: {}",
                            status.status.as_str()
                        );
                    }
                }
                other => {
                    bail!("computer audit chain failed closed: {}", other.as_str());
                }
            }

            if let Some(existing) = rows.iter().find(|row| {
                row.event_kind == event.kind.as_byte() && row.proposal_id == event.proposal_id
            }) {
                anyhow::ensure!(
                    existing.event_kind == event.kind.as_byte(),
                    "computer audit guidance replay kind mismatch"
                );
                return Ok(());
            }

            let sequence = head.confirmed_sequence.saturating_add(1);
            anyhow::ensure!(sequence >= 1, "computer audit sequence overflow");
            let monotonic = next_monotonic(inner.last_monotonic);
            let wall_unix_millis = chrono::Utc::now().timestamp_millis();
            let entry = build_guidance_entry(
                event,
                sequence,
                head.confirmed_mac,
                inner.current_key_version,
                monotonic,
                wall_unix_millis,
            )?;
            let entry_bytes = entry.encode();
            let hmac_key = inner
                .hmac_keys
                .get(&inner.current_key_version)
                .ok_or_else(|| anyhow!("computer audit HMAC key missing"))?;
            let mac = super::entry_mac(hmac_key.as_ref(), &entry_bytes);

            let pending = ComputerAuditSealedHeadV1::with_pending(
                head.sealed_generation,
                head.confirmed_sequence,
                head.confirmed_mac,
                head.confirmed_key_version,
                inner.database_instance_id,
                entry_bytes,
                mac,
                head.confirmed_sequence,
                head.confirmed_mac,
                inner.current_key_version,
                inner.database_instance_id,
            );
            match self.cas_head(&view, &pending).await {
                Ok(pending_view) => view = pending_view,
                Err(CasOutcome::Conflict) => continue,
                Err(CasOutcome::Fatal(error)) => return Err(error),
            }

            let row = ComputerAuditEntryRow {
                sequence,
                entry_bytes,
                mac,
                event_kind: event.kind.as_byte(),
                proposal_id: event.proposal_id,
                key_version: inner.current_key_version,
            };
            self.db
                .insert_computer_audit_entry(row)
                .await
                .context("inserting computer audit entry")?;

            let confirmed = ComputerAuditSealedHeadV1::confirmed_only(
                head.sealed_generation.saturating_add(1).max(1),
                sequence,
                mac,
                inner.current_key_version,
                inner.database_instance_id,
            );
            match self.cas_head(&view, &confirmed).await {
                Ok(_) => {
                    inner.last_monotonic = monotonic;
                    return Ok(());
                }
                Err(CasOutcome::Conflict) => continue,
                Err(CasOutcome::Fatal(error)) => return Err(error),
            }
        }
        bail!("computer audit chain CAS retries exhausted")
    }

    async fn recover_pending(
        &self,
        inner: &mut ChainInner,
        view: &crate::secure_key::SealedStateView,
        head: &ComputerAuditSealedHeadV1,
        rows: &[ComputerAuditEntryRow],
    ) -> Result<()> {
        anyhow::ensure!(
            head.pending_present,
            "pending recovery without pending head"
        );
        let pending_entry = ComputerAuditEntryV1::decode(&head.pending_entry)
            .map_err(|e| anyhow!("pending audit entry decode: {e}"))?;
        let expected_seq = head.confirmed_sequence.saturating_add(1);
        anyhow::ensure!(
            pending_entry.sequence == expected_seq,
            "pending audit sequence does not continue the confirmed head"
        );

        let last_seq = rows.last().map(|row| row.sequence).unwrap_or(0);
        if last_seq < expected_seq {
            let row = ComputerAuditEntryRow {
                sequence: pending_entry.sequence,
                entry_bytes: head.pending_entry,
                mac: head.pending_mac,
                event_kind: pending_entry.event_kind.as_byte(),
                proposal_id: pending_entry.proposal_id,
                key_version: pending_entry.key_version,
            };
            self.db
                .insert_computer_audit_entry(row)
                .await
                .context("reconstructing pending computer audit entry")?;
        } else if last_seq == expected_seq {
            let last = rows.last().expect("last_seq == expected_seq implies a row");
            anyhow::ensure!(
                last.entry_bytes == head.pending_entry && last.mac == head.pending_mac,
                "pending audit entry does not match the durable log"
            );
        } else {
            bail!("computer audit chain failed closed: sealed_head_behind_database");
        }

        let confirmed = ComputerAuditSealedHeadV1::confirmed_only(
            head.sealed_generation.saturating_add(1).max(1),
            pending_entry.sequence,
            head.pending_mac,
            pending_entry.key_version,
            inner.database_instance_id,
        );
        match self.cas_head(view, &confirmed).await {
            Ok(_) => {
                inner.last_monotonic = inner.last_monotonic.max(pending_entry.monotonic_nanos);
                Ok(())
            }
            Err(CasOutcome::Conflict) => {
                // Lost-ack: the promoter already committed. Re-verify on retry.
                Ok(())
            }
            Err(CasOutcome::Fatal(error)) => Err(error),
        }
    }

    async fn cas_head(
        &self,
        expected: &crate::secure_key::SealedStateView,
        new_head: &ComputerAuditSealedHeadV1,
    ) -> Result<crate::secure_key::SealedStateView, CasOutcome> {
        let payload = SealedPayload::new(new_head.encode())
            .map_err(|e| CasOutcome::Fatal(anyhow!("computer audit sealed head payload: {e}")))?;
        match self
            .keys
            .sealed_compare_and_swap(
                COMPUTER_AUDIT_HEAD_V1_NAMESPACE,
                expected.meta.generation,
                expected.meta.payload_digest,
                payload,
            )
            .await
        {
            Ok(view) => Ok(view),
            Err(SecureKeyError::Conflict { .. }) => Err(CasOutcome::Conflict),
            Err(SecureKeyError::Busy) => Err(CasOutcome::Conflict),
            Err(error) => Err(CasOutcome::Fatal(anyhow!(
                "computer audit sealed head CAS: {error}"
            ))),
        }
    }

    async fn ensure_key(
        &self,
        keys: &mut HashMap<u32, SecureKeyBytes>,
        version: u32,
    ) -> Result<()> {
        if keys.contains_key(&version) {
            return Ok(());
        }
        let (loaded, bytes) = self
            .keys
            .load_version(COMPUTER_AUDIT_V1_NAMESPACE, i64::from(version))
            .await
            .with_context(|| format!("loading computer audit HMAC key version {version}"))?;
        anyhow::ensure!(
            u32::try_from(loaded).ok() == Some(version),
            "computer audit key version mismatch"
        );
        keys.insert(version, bytes);
        Ok(())
    }

    async fn verify_loaded(&self, inner: &ChainInner) -> Result<AuditVerifyResult> {
        let view = match self
            .keys
            .sealed_load(COMPUTER_AUDIT_HEAD_V1_NAMESPACE)
            .await
        {
            Ok(view) => view,
            Err(_) => return Ok(empty_status(AuditVerifyStatus::UnavailableSecureStore)),
        };
        let head = match decode_head(view.payload.as_slice()) {
            Ok(head) => head,
            Err(_) => {
                return Ok(corrupt_from_instance(inner.database_instance_id));
            }
        };
        let rows = self.db.list_computer_audit_entries().await?;
        verify_with(inner, Some(&head), Some(&rows))
    }
}

enum CasOutcome {
    Conflict,
    Fatal(anyhow::Error),
}

fn is_guidance_kind(kind: AuditEventKind) -> bool {
    matches!(
        kind.as_byte(),
        GUIDANCE_PROPOSAL_CREATED
            | GUIDANCE_PROPOSAL_ACCEPTED
            | GUIDANCE_PROPOSAL_REJECTED
            | GUIDANCE_PROPOSAL_EXPIRED
    )
}

fn decode_head(bytes: &[u8]) -> Result<ComputerAuditSealedHeadV1> {
    ComputerAuditSealedHeadV1::decode(bytes).map_err(|e| anyhow!("computer audit sealed head: {e}"))
}

fn identity_bytes(identity: &InstallationIdentity) -> Result<[u8; 16]> {
    let hex = identity.as_hex();
    anyhow::ensure!(hex.len() == 32, "installation identity hex length");
    let mut out = [0u8; 16];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("installation identity hex"))?;
    }
    Ok(out)
}

fn max_monotonic(rows: &[ComputerAuditEntryRow]) -> u64 {
    rows.iter()
        .filter_map(|row| ComputerAuditEntryV1::decode(&row.entry_bytes).ok())
        .map(|entry| entry.monotonic_nanos)
        .max()
        .unwrap_or(0)
}

fn next_monotonic(last: u64) -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let elapsed = START.get_or_init(Instant::now).elapsed().as_nanos() as u64;
    last.saturating_add(1).max(elapsed.max(1))
}

fn chain_entries(rows: &[ComputerAuditEntryRow]) -> Vec<ChainEntry> {
    rows.iter()
        .map(|row| ChainEntry {
            sequence: row.sequence,
            entry_bytes: row.entry_bytes,
            mac: row.mac,
        })
        .collect()
}

fn verify_with(
    inner: &ChainInner,
    head: Option<&ComputerAuditSealedHeadV1>,
    rows: Option<&[ComputerAuditEntryRow]>,
) -> Result<AuditVerifyResult> {
    let entries = rows.map(chain_entries);
    let key_map: HashMap<u32, Vec<u8>> = inner
        .hmac_keys
        .iter()
        .map(|(version, key)| (*version, key.as_ref().to_vec()))
        .collect();
    Ok(verify_chain(head, entries.as_deref(), |version| {
        key_map.get(&version).cloned()
    }))
}

fn empty_status(status: AuditVerifyStatus) -> AuditVerifyResult {
    AuditVerifyResult {
        status,
        confirmed_sequence: 0,
        confirmed_mac: [0u8; 32],
        sealed_generation: 0,
        database_instance_id: [0u8; 16],
        entry_count: 0,
    }
}

fn corrupt_from_instance(database_instance_id: [u8; 16]) -> AuditVerifyResult {
    AuditVerifyResult {
        status: AuditVerifyStatus::Corrupt,
        confirmed_sequence: 0,
        confirmed_mac: [0u8; 32],
        sealed_generation: 0,
        database_instance_id,
        entry_count: 0,
    }
}

fn build_guidance_entry(
    event: &GuidanceAuditAppend,
    sequence: u64,
    previous_mac: [u8; 32],
    key_version: u32,
    monotonic_nanos: u64,
    wall_unix_millis: i64,
) -> Result<ComputerAuditEntryV1> {
    let mut present_bits_mask = present_bits::SESSION_ID
        | present_bits::DELEGATION_ID
        | present_bits::PROPOSAL_ID
        | present_bits::CANONICAL_PROJECT_DIGEST
        | present_bits::PROVIDER_DIGEST
        | present_bits::MODEL_DIGEST;
    if event.disposition.is_some() {
        present_bits_mask |= present_bits::DISPOSITION;
    }
    if event.scope.is_some() {
        present_bits_mask |= present_bits::SCOPE;
    }
    if event.config_generation != 0 {
        present_bits_mask |= present_bits::JOURNAL_VERSION;
    }
    if event.rule_kind_bits != 0 {
        present_bits_mask |= present_bits::RULE_KIND_BITS;
    }
    let entry = ComputerAuditEntryV1 {
        event_kind: event.kind,
        present_bits: present_bits_mask,
        sequence,
        previous_mac,
        session_id: event.session_id,
        delegation_id: event.delegation_id,
        action_id: [0u8; 16],
        operation_id: [0u8; 16],
        proposal_id: event.proposal_id,
        disposition: event.disposition.map(|d| d as u8).unwrap_or(0),
        scope: event.scope.map(|s| s as u8).unwrap_or(0),
        canonical_project_digest: event.canonical_project_digest,
        provider_digest: event.provider_digest,
        model_digest: event.model_digest,
        physical_target_digest: [0u8; 32],
        focus_digest: [0u8; 32],
        observation_digest: [0u8; 32],
        host_lease_digest: [0u8; 32],
        record_digest: [0u8; 32],
        ask_yolo: 0,
        action_class: 0,
        journal_state: 0,
        verification_state: 0,
        journal_version: event.config_generation,
        monotonic_nanos,
        wall_unix_millis,
        error_code: 0,
        rule_kind_bits: event.rule_kind_bits,
        key_version,
    };
    entry
        .validate_presence()
        .map_err(|e| anyhow!("computer audit guidance entry: {e}"))?;
    anyhow::ensure!(
        entry.encode().len() == ENTRY_LEN && ENTRY_LEN == COMPUTER_AUDIT_ENTRY_LEN,
        "computer audit entry length"
    );
    Ok(entry)
}

#[cfg(test)]
pub(crate) struct TestAuditHarness {
    pub db: Arc<Db>,
    pub chain: Arc<ComputerAuditChain>,
    actor: Option<crate::secure_key::SecureKeyActor>,
}

#[cfg(test)]
impl TestAuditHarness {
    pub async fn new() -> Self {
        use std::sync::Arc as StdArc;

        use crate::db::secure_key::SEALED_STATE_CONSUMER_KIND;
        use crate::secure_key::fake::FakeNativeStore;
        use crate::secure_key::{MapReconciler, SecureKeyActor};

        let db = Arc::new(Db::open_in_memory().unwrap());
        let db_for_actor = db.as_ref().clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("computer-audit-test-boot".into())
            .spawn(move || {
                let store = FakeNativeStore::new();
                let recon = StdArc::new(
                    MapReconciler::new().with_kind(SEALED_STATE_CONSUMER_KIND, |_| true),
                );
                let _ = tx.send(SecureKeyActor::start_with_store(
                    db_for_actor,
                    Box::new(store),
                    recon,
                ));
            })
            .expect("spawn computer audit test boot");
        let actor = rx
            .await
            .expect("computer audit boot channel")
            .expect("computer audit actor");
        let chain = Arc::new(
            ComputerAuditChain::try_open(db.clone(), actor.handle())
                .await
                .expect("computer audit chain open"),
        );
        Self {
            db,
            chain,
            actor: Some(actor),
        }
    }
}

#[cfg(test)]
impl Drop for TestAuditHarness {
    fn drop(&mut self) {
        if let Some(actor) = self.actor.take() {
            let _ = std::thread::Builder::new()
                .name("computer-audit-test-shutdown".into())
                .spawn(move || drop(actor))
                .and_then(|handle| handle.join().map_err(|_| std::io::Error::other("join")));
        }
    }
}

#[cfg(test)]
fn sample_event(kind: AuditEventKind, proposal: u8) -> GuidanceAuditAppend {
    let mut id = [0u8; 16];
    id[0] = proposal;
    id[15] = proposal;
    let mut digest = [0u8; 32];
    digest[0] = proposal;
    digest[31] = proposal.saturating_add(1);
    GuidanceAuditAppend {
        kind,
        proposal_id: id,
        session_id: id,
        delegation_id: id,
        canonical_project_digest: digest,
        provider_digest: digest,
        model_digest: digest,
        config_generation: 1,
        rule_kind_bits: 0b0001,
        disposition: match kind {
            AuditEventKind::GuidanceProposalAccepted => Some(Disposition::AcceptedPersistent),
            AuditEventKind::GuidanceProposalRejected => Some(Disposition::Rejected),
            AuditEventKind::GuidanceProposalExpired => Some(Disposition::Expired),
            _ => None,
        },
        scope: match kind {
            AuditEventKind::GuidanceProposalAccepted => Some(GuidanceScope::ProjectProviderModel),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_chain_verifies() {
        let harness = TestAuditHarness::new().await;
        assert!(harness.chain.is_available());
        assert_eq!(
            harness.chain.verify().await.status,
            AuditVerifyStatus::Verified
        );
        assert_eq!(harness.chain.verify().await.confirmed_sequence, 0);
    }

    #[tokio::test]
    async fn create_accept_reject_form_an_unbroken_chain() {
        let harness = TestAuditHarness::new().await;
        harness
            .chain
            .append_guidance(sample_event(AuditEventKind::GuidanceProposalCreated, 1))
            .await
            .unwrap();
        harness
            .chain
            .append_guidance(sample_event(AuditEventKind::GuidanceProposalAccepted, 1))
            .await
            .unwrap();
        harness
            .chain
            .append_guidance(sample_event(AuditEventKind::GuidanceProposalCreated, 2))
            .await
            .unwrap();
        harness
            .chain
            .append_guidance(sample_event(AuditEventKind::GuidanceProposalRejected, 2))
            .await
            .unwrap();
        let result = harness.chain.verify().await;
        assert_eq!(result.status, AuditVerifyStatus::Verified);
        assert_eq!(result.confirmed_sequence, 4);
        assert_eq!(result.entry_count, 4);
        let rows = harness.db.list_computer_audit_entries().await.unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].sequence, 1);
        assert_eq!(rows[3].event_kind, GUIDANCE_PROPOSAL_REJECTED);
    }

    #[tokio::test]
    async fn guidance_append_is_idempotent() {
        let harness = TestAuditHarness::new().await;
        let event = sample_event(AuditEventKind::GuidanceProposalCreated, 9);
        harness.chain.append_guidance(event.clone()).await.unwrap();
        harness.chain.append_guidance(event).await.unwrap();
        assert_eq!(harness.chain.verify().await.confirmed_sequence, 1);
        assert_eq!(
            harness
                .db
                .list_computer_audit_entries()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn reopen_verifies_the_same_unbroken_chain() {
        let harness = TestAuditHarness::new().await;
        harness
            .chain
            .append_guidance(sample_event(AuditEventKind::GuidanceProposalCreated, 4))
            .await
            .unwrap();
        harness
            .chain
            .append_guidance(sample_event(AuditEventKind::GuidanceProposalExpired, 4))
            .await
            .unwrap();
        let handle = harness.actor.as_ref().unwrap().handle();
        let reopened = ComputerAuditChain::try_open(harness.db.clone(), handle)
            .await
            .unwrap();
        let result = reopened.verify().await;
        assert_eq!(result.status, AuditVerifyStatus::Verified);
        assert_eq!(result.confirmed_sequence, 2);
        assert!(reopened.is_available());
    }

    #[tokio::test]
    async fn sqlite_tail_deletion_fails_closed() {
        let harness = TestAuditHarness::new().await;
        harness
            .chain
            .append_guidance(sample_event(AuditEventKind::GuidanceProposalCreated, 1))
            .await
            .unwrap();
        harness
            .chain
            .append_guidance(sample_event(AuditEventKind::GuidanceProposalAccepted, 1))
            .await
            .unwrap();
        // Bypass the append-only trigger to simulate a tamper of the log.
        let tamper = harness
            .db
            .write(|conn| {
                conn.execute("PRAGMA writable_schema = ON", [])?;
                conn.execute("DROP TRIGGER computer_audit_entries_immutable_delete", [])?;
                conn.execute("DELETE FROM computer_audit_entries WHERE sequence = 2", [])?;
                Ok(())
            })
            .await;
        assert!(tamper.is_ok(), "{tamper:?}");
        let status = harness.chain.verify().await.status;
        assert_ne!(status, AuditVerifyStatus::Verified);
        assert!(
            matches!(
                status,
                AuditVerifyStatus::Corrupt | AuditVerifyStatus::DatabaseBehindSealedHead
            ),
            "{status:?}"
        );
        let err = harness
            .chain
            .append_guidance(sample_event(AuditEventKind::GuidanceProposalCreated, 9))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("failed closed") || err.to_string().contains("not available"),
            "{err}"
        );
        assert!(!harness.chain.is_available());
    }
}
