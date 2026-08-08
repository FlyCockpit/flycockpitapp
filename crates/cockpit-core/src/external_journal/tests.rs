//! End-to-end journal behaviour: pre-dispatch ordering, post-handoff
//! fallback, recovery, exactly-once, and redaction.
//!
//! No real provider, network, sleep, or process-global environment mutation.
//! Time is injected as `now_wall_ms`; every filesystem artefact lives under a
//! per-test temporary directory.

use std::path::PathBuf;
use std::sync::Mutex;

use uuid::Uuid;

use cockpit_db::Db;
use cockpit_db::external_journal::{
    CapsulePartition, EXTERNAL_JOURNAL_ADMISSION_CAPSULES, EXTERNAL_JOURNAL_PREPARED_TTL_MS,
    EXTERNAL_JOURNAL_UNRESOLVED_CRITICAL_MS, ExternalJournalState,
};

use super::capsule::{CAPSULE_BYTES, CapsuleSlot, SLOT_BYTES};
use super::keys::SpoolKeyRing;
use super::projection::{Digest, OperationBody, SafeToken, SanitizedProjection};
use super::spool::{Spool, SpoolAccess, SpoolFaults};
use super::{DbFaults, DispatchTicket, ExternalJournal, ExternalJournalError, OutcomeDurability};

const T0: i64 = 1_700_000_000_000;

fn owner() -> SafeToken {
    SafeToken::parse("session-owner").expect("valid owner token")
}

fn key(value: &str) -> SafeToken {
    SafeToken::parse(value).expect("valid idempotency key")
}

/// A fake provider that records every call it receives. A test asserting
/// "zero dispatch" asserts this stayed empty.
#[derive(Default)]
struct FakeProvider {
    calls: Mutex<Vec<Uuid>>,
}

impl FakeProvider {
    fn call(&self, ticket: &DispatchTicket) {
        self.calls
            .lock()
            .expect("provider mutex")
            .push(ticket.operation_id);
    }

    fn count(&self) -> usize {
        self.calls.lock().expect("provider mutex").len()
    }
}

struct Env {
    tmp: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            tmp: tempfile::TempDir::new().expect("tempdir"),
        }
    }

    fn db_path(&self) -> PathBuf {
        self.tmp.path().join("journal.db")
    }

    fn spool_root(&self) -> PathBuf {
        self.tmp.path().join("spool")
    }

    fn db(&self) -> Db {
        Db::open(&self.db_path()).expect("open db")
    }

    fn spool(&self) -> Spool {
        Spool::open_at(&self.spool_root(), SpoolAccess::Create).expect("open spool")
    }

    fn journal(&self) -> ExternalJournal {
        self.journal_with_keys(keys_v1())
    }

    fn journal_with_keys(&self, keys: SpoolKeyRing) -> ExternalJournal {
        ExternalJournal::new(self.db(), self.spool(), keys)
    }

    fn capsule_path(&self, capsule_uuid: Uuid) -> PathBuf {
        self.spool_root()
            .join("capsules")
            .join(format!("{capsule_uuid}.v1"))
    }
}

fn keys_v1() -> SpoolKeyRing {
    SpoolKeyRing::for_test(&[(1, [0x11u8; 32])], 1).expect("key ring")
}

fn inference_projection() -> SanitizedProjection {
    SanitizedProjection::new(OperationBody::InferenceRecovery {
        request_digest: Digest::of(b"redacted-request"),
        provider_digest: Digest::of(b"provider:model"),
    })
}

#[tokio::test]
async fn inference_journal_precedes_provider_construction() {
    let env = Env::new();
    let journal = env.journal();
    let provider = FakeProvider::default();
    let projection = inference_projection();
    let record = journal
        .prepare(&owner(), &key("inference-1"), &projection, T0)
        .await
        .unwrap();
    assert_eq!(provider.count(), 0);
    let ticket = journal
        .begin_dispatch(record.operation_id, &projection, T0 + 1)
        .await
        .unwrap();
    assert_eq!(provider.count(), 0);
    provider.call(&ticket);
    assert_eq!(provider.count(), 1);
}

#[tokio::test]
async fn inference_journal_durability_failure_sends_nothing() {
    let env = Env::new();
    let journal = env.journal();
    let provider = FakeProvider::default();
    let projection = inference_projection();
    journal.set_db_faults(DbFaults {
        fail_prepared_commit: true,
        ..DbFaults::default()
    });
    assert!(
        journal
            .prepare(&owner(), &key("inference-prepare"), &projection, T0)
            .await
            .is_err()
    );
    assert_eq!(provider.count(), 0);

    let journal = env.journal();
    let record = journal
        .prepare(&owner(), &key("inference-dispatch"), &projection, T0)
        .await
        .unwrap();
    journal.set_db_faults(DbFaults {
        fail_dispatching_commit: true,
        ..DbFaults::default()
    });
    assert!(
        journal
            .begin_dispatch(record.operation_id, &projection, T0 + 1)
            .await
            .is_err()
    );
    assert_eq!(provider.count(), 0);
}

async fn inference_primary_failure_journal_success_case() {
    let env = Env::new();
    let journal = env.journal();
    let provider = FakeProvider::default();
    let projection = inference_projection();
    let record = journal
        .prepare(&owner(), &key("incident-85acj7"), &projection, T0)
        .await
        .unwrap();
    let ticket = journal
        .begin_dispatch(record.operation_id, &projection, T0 + 1)
        .await
        .unwrap();
    let missing_session = Uuid::new_v4();
    assert!(
        env.db()
            .insert_inference_request(
                "incident-85acj7",
                missing_session,
                &serde_json::json!({"redacted": true}),
                cockpit_db::db::session_log::InferenceRequestStatus::Pending,
            )
            .await
            .is_err()
    );
    provider.call(&ticket);
    assert_eq!(provider.count(), 1);
}

#[tokio::test]
async fn inference_primary_failure_journal_success() {
    inference_primary_failure_journal_success_case().await;
}

#[tokio::test]
async fn inference_submission_unknown_is_not_retried() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "inference-unknown").await;
    journal
        .record_outcome(&mut ticket, ExternalJournalState::SubmissionUnknown, T0 + 1)
        .await
        .unwrap();
    let record = env
        .db()
        .external_operation(ticket.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::SubmissionUnknown);
    assert!(!record.retry_permitted());
}

#[tokio::test]
async fn inference_session_tombstone_prevents_resurrection() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "inference-tombstone").await;
    env.db()
        .tombstone_external_journal_session(&owner(), T0 + 1)
        .await
        .unwrap();
    journal
        .record_outcome(&mut ticket, ExternalJournalState::SubmissionUnknown, T0 + 2)
        .await
        .unwrap();
    assert!(
        env.db()
            .external_journal_session_tombstoned(&owner())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn inference_85acj7_regression() {
    inference_primary_failure_journal_success_case().await;
}

#[test]
fn inference_audit_sentinels_are_digest_only() {
    let sentinels = [
        "raw prompt",
        "Bearer credential",
        "x-secret-header",
        "DATABASE disk image is malformed",
        "SQL INSERT INTO inference_requests",
        "/home/user/private",
    ];
    let projection = SanitizedProjection::new(OperationBody::InferenceRecovery {
        request_digest: Digest::of(sentinels.join("|").as_bytes()),
        provider_digest: Digest::of(b"provider:model"),
    });
    let encoded = String::from_utf8(projection.encode().unwrap()).unwrap();
    for sentinel in sentinels {
        assert!(!encoded.contains(sentinel));
    }
}

fn projection() -> SanitizedProjection {
    SanitizedProjection::new(OperationBody::ComputerInput {
        target_digest: Digest::of(b"display-0"),
        action_count: 4,
    })
}

/// Prepare and provision one operation, returning its ticket.
async fn dispatch(journal: &ExternalJournal, idempotency_key: &str) -> DispatchTicket {
    let projection = projection();
    let record = journal
        .prepare(&owner(), &key(idempotency_key), &projection, T0)
        .await
        .expect("prepare");
    journal
        .begin_dispatch(record.operation_id, &projection, T0)
        .await
        .expect("begin dispatch")
}

// ---- criterion 2: pre-dispatch ordering ---------------------------------

#[tokio::test]
async fn external_journal_pre_dispatch_commits_everything_before_the_provider_call() {
    let env = Env::new();
    let journal = env.journal();
    let provider = FakeProvider::default();

    let projection = projection();
    let record = journal
        .prepare(&owner(), &key("k1"), &projection, T0)
        .await
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::Prepared);
    assert_eq!(record.version, 1);
    // Nothing exists on disk until dispatch provisioning starts.
    assert!(journal.spool().list_capsules().unwrap().is_empty());

    let ticket = journal
        .begin_dispatch(record.operation_id, &projection, T0)
        .await
        .unwrap();
    // The provider is called only after `begin_dispatch` returns Ok.
    provider.call(&ticket);

    let committed = env
        .db()
        .external_operation(record.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(committed.state, ExternalJournalState::Dispatching);
    assert_eq!(committed.version, 2);
    assert!(committed.dispatch_may_have_started());

    let path = env.capsule_path(ticket.capsule_uuid());
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        CAPSULE_BYTES as u64
    );

    let keys = keys_v1();
    let slot0 = CapsuleSlot::decode(
        &journal.spool().read_slot(ticket.capsule_uuid(), 0).unwrap(),
        record.operation_id,
        &keys,
    )
    .unwrap();
    assert_eq!(slot0.state, ExternalJournalState::Prepared);
    assert_eq!(slot0.journal_version, 1);
    let slot1 = CapsuleSlot::decode(
        &journal.spool().read_slot(ticket.capsule_uuid(), 1).unwrap(),
        record.operation_id,
        &keys,
    )
    .unwrap();
    assert_eq!(slot1.state, ExternalJournalState::Dispatching);
    assert_eq!(slot1.journal_version, 2);
    assert_eq!(ticket.active_slot(), 1);
    assert_eq!(provider.count(), 1);
}

/// Every pre-handoff failure mode must leave the record at `prepared`, the
/// spool empty, the capacity ledger empty, and the provider uncalled.
async fn assert_zero_dispatch(env: &Env, journal: &ExternalJournal, idempotency_key: &str) {
    let provider = FakeProvider::default();
    let projection = projection();
    let record = journal
        .prepare(&owner(), &key(idempotency_key), &projection, T0)
        .await
        .unwrap();
    let error = journal
        .begin_dispatch(record.operation_id, &projection, T0)
        .await
        .expect_err("dispatch must not be provisioned");
    // The provider is unreachable without a ticket.
    assert_eq!(provider.count(), 0, "provider was called despite {error}");

    let db = env.db();
    let after = db
        .external_operation(record.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.state, ExternalJournalState::Prepared);
    assert_eq!(after.version, 1);
    assert!(
        !after.dispatch_may_have_started(),
        "a failed provisioning must keep durable no-dispatch proof"
    );
    assert!(journal.spool().list_capsules().unwrap().is_empty());
    assert_eq!(
        db.external_journal_capacity()
            .await
            .unwrap()
            .total_capsules(),
        0
    );
}

#[tokio::test]
async fn external_journal_pre_dispatch_capsule_reservation_failure_yields_zero_dispatch() {
    let env = Env::new();
    let journal = env.journal();
    journal.set_db_faults(DbFaults {
        fail_capsule_reservation: true,
        ..DbFaults::default()
    });
    assert_zero_dispatch(&env, &journal, "k1").await;
}

#[tokio::test]
async fn external_journal_pre_dispatch_allocation_failure_yields_zero_dispatch() {
    let env = Env::new();
    let journal = env.journal();
    journal.spool().set_faults(SpoolFaults {
        fail_allocate: true,
        ..SpoolFaults::default()
    });
    assert_zero_dispatch(&env, &journal, "k1").await;
}

#[tokio::test]
async fn external_journal_pre_dispatch_fsync_failure_yields_zero_dispatch() {
    for faults in [
        SpoolFaults {
            fail_file_fsync: true,
            ..SpoolFaults::default()
        },
        SpoolFaults {
            fail_parent_fsync: true,
            ..SpoolFaults::default()
        },
        SpoolFaults {
            fail_sentinel_verify: true,
            ..SpoolFaults::default()
        },
    ] {
        let env = Env::new();
        let journal = env.journal();
        journal.spool().set_faults(faults);
        assert_zero_dispatch(&env, &journal, "k1").await;
    }
}

#[tokio::test]
async fn external_journal_pre_dispatch_slot_write_failure_yields_zero_dispatch() {
    for slot in [0u8, 1] {
        let env = Env::new();
        let journal = env.journal();
        journal.spool().set_faults(SpoolFaults {
            fail_slot_write: Some(slot),
            ..SpoolFaults::default()
        });
        assert_zero_dispatch(&env, &journal, "k1").await;
    }
}

#[tokio::test]
async fn external_journal_pre_dispatch_db_commit_failure_yields_zero_dispatch() {
    let env = Env::new();
    let journal = env.journal();
    journal.set_db_faults(DbFaults {
        fail_dispatching_commit: true,
        ..DbFaults::default()
    });
    assert_zero_dispatch(&env, &journal, "k1").await;
}

#[tokio::test]
async fn external_journal_pre_dispatch_full_admission_partition_yields_zero_dispatch() {
    let env = Env::new();
    let db = env.db();
    // Saturate the admission partition through the ledger.
    db.write(|conn| {
        for index in 0..EXTERNAL_JOURNAL_ADMISSION_CAPSULES {
            let operation_id = Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO external_journal_operations (
                     operation_id, operation_kind, owner_session_id, idempotency_key,
                     payload_digest, payload_len, state, version,
                     created_at_wall_ms, updated_at_wall_ms
                 ) VALUES (?1, 'seed', 'seed-session', ?2, ?3, 0, 'prepared', 1, 0, 0)",
                rusqlite::params![operation_id, index.to_string(), "c".repeat(64)],
            )?;
            conn.execute(
                "INSERT INTO external_journal_spool_capsules (
                     operation_id, capsule_uuid, key_version, allocated_bytes,
                     capacity_partition, quarantined, created_at_wall_ms
                 ) VALUES (?1, ?2, 1, 65536, 'admission', 0, 0)",
                rusqlite::params![operation_id, Uuid::new_v4().to_string()],
            )?;
        }
        Ok(())
    })
    .await
    .unwrap();

    let journal = env.journal();
    let projection = projection();
    let record = journal
        .prepare(&owner(), &key("k1"), &projection, T0)
        .await
        .unwrap();
    let error = journal
        .begin_dispatch(record.operation_id, &projection, T0)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ExternalJournalError::CapacityExhausted(_)),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        db.external_operation(record.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::Prepared
    );
    assert!(journal.spool().list_capsules().unwrap().is_empty());

    // The recovery reserve is untouched by the admission saturation.
    let admission = db
        .reserve_external_journal_capsule(
            record.operation_id,
            Uuid::new_v4(),
            1,
            CapsulePartition::Recovery,
            false,
            T0,
        )
        .await
        .unwrap();
    assert!(matches!(
        admission,
        cockpit_db::external_journal::CapsuleAdmission::Reserved(_)
    ));
}

// ---- criterion 11: post-handoff capsule behaviour ------------------------

#[tokio::test]
async fn external_journal_recovery_capsule_db_failure_after_handoff_writes_next_slot() {
    let env = Env::new();
    let journal = env.journal();
    let provider = FakeProvider::default();
    let mut ticket = dispatch(&journal, "k1").await;
    provider.call(&ticket);

    let path = env.capsule_path(ticket.capsule_uuid());
    let before = std::fs::metadata(&path).unwrap();

    journal.set_db_faults(DbFaults {
        fail_outcome_commit: true,
        ..DbFaults::default()
    });
    let durability = journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
        .await
        .unwrap();
    assert_eq!(durability, OutcomeDurability::SpoolFallback);
    assert_eq!(ticket.active_slot(), 0, "the inactive slot must be reused");
    assert_eq!(ticket.version(), 3);

    // No new file, directory entry, or allocation.
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(after.len(), before.len());
    assert_eq!(after.len(), CAPSULE_BYTES as u64);
    assert_eq!(journal.spool().list_capsules().unwrap().len(), 1);

    let keys = keys_v1();
    let slot = CapsuleSlot::decode(
        &journal.spool().read_slot(ticket.capsule_uuid(), 0).unwrap(),
        ticket.operation_id,
        &keys,
    )
    .unwrap();
    assert_eq!(slot.state, ExternalJournalState::Accepted);
    assert_eq!(slot.journal_version, 3);
    // SQLite has not moved: it is still the ambiguous `dispatching` fact.
    assert_eq!(
        env.db()
            .external_operation(ticket.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::Dispatching
    );
}

#[tokio::test]
async fn external_journal_recovery_capsule_restart_imports_the_highest_state() {
    let env = Env::new();
    let operation_id = {
        let journal = env.journal();
        let mut ticket = dispatch(&journal, "k1").await;
        journal.set_db_faults(DbFaults {
            fail_outcome_commit: true,
            ..DbFaults::default()
        });
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
            .await
            .unwrap();
        ticket.operation_id
    };

    // Restart: fresh database handle, fresh spool handle, same bytes.
    let journal = env.journal();
    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(report.scanned, 1);
    assert_eq!(report.imported, 1);
    assert_eq!(report.quarantined, 0);
    let record = env
        .db()
        .external_operation(operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::Accepted);
    assert_eq!(record.version, 3);

    // A second pass is idempotent: two recovery workers may poll.
    let again = journal.recover(T0 + 200).await.unwrap();
    assert_eq!(again.imported, 0);
    assert_eq!(again.idempotent, 1);
    let events = env
        .db()
        .external_operation_events(operation_id)
        .await
        .unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events.iter().filter(|event| event.terminal).count(), 0);
}

#[tokio::test]
async fn external_journal_recovery_capsule_corruption_quarantines_and_blocks() {
    let env = Env::new();
    let journal = env.journal();
    let ticket = dispatch(&journal, "k1").await;

    // Corrupt both slots: authentication fails, so nothing is imported.
    let path = env.capsule_path(ticket.capsule_uuid());
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[100] ^= 0xff;
    bytes[SLOT_BYTES + 100] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(report.quarantined, 1);
    assert_eq!(report.imported, 0);
    assert!(journal.spool().list_capsules().unwrap().is_empty());
    assert_eq!(journal.spool().list_quarantined().unwrap().len(), 1);

    // Quarantine blocks new external work.
    let error = journal.ensure_dispatch_allowed().await.unwrap_err();
    assert!(
        matches!(error, ExternalJournalError::DispatchBlocked(_)),
        "unexpected error: {error:?}"
    );

    // CORRECTED EXPECTATION (was `Dispatching`). A quarantined capsule means
    // there is no authentic evidence for a record that already passed the
    // `dispatching` commit, which is exactly the prompt's "crash after
    // `dispatching` without evidence becomes `submission_unknown`" edge case.
    // Leaving the row at `dispatching` was wrong twice over: it claimed a
    // transient pre-handoff state for work that may have produced an external
    // effect, and it kept the record out of the unresolved age report, so
    // ambiguous post-handoff work would never warn at 15m or go critical at
    // 24h and would never appear in `list_unresolved_external_operations`.
    let record = env
        .db()
        .external_operation(ticket.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::SubmissionUnknown);
    assert!(record.state.is_unresolved());
    // The record became unresolved when recovery converted it at T0 + 100, so
    // it turns critical 24h after that, not 24h after dispatch.
    const CONVERTED_AT: i64 = T0 + 100;
    let age = journal
        .status(CONVERTED_AT + EXTERNAL_JOURNAL_UNRESOLVED_CRITICAL_MS)
        .await
        .unwrap()
        .age;
    assert_eq!(age.unresolved, 1);
    assert_eq!(age.critical, 1);
}

#[tokio::test]
async fn external_journal_recovery_capsule_equal_version_disagreement_quarantines() {
    let env = Env::new();
    let journal = env.journal();
    let ticket = dispatch(&journal, "k1").await;
    let keys = keys_v1();

    // Two authentic slots at the same version that disagree.
    let conflicting = super::capsule::CapsuleSlot {
        slot_index: 0,
        operation_id: ticket.operation_id,
        journal_version: 2,
        key_version: 1,
        state: ExternalJournalState::Rejected,
        updated_at_wall_ms: T0,
        projection: projection().encode().unwrap(),
    };
    journal
        .spool()
        .write_slot(
            ticket.capsule_uuid(),
            0,
            &conflicting.encode(&keys).unwrap(),
        )
        .unwrap();

    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(report.quarantined, 1);
    assert_eq!(report.imported, 0);
}

#[tokio::test]
async fn external_journal_recovery_capsule_total_medium_failure_is_integrity_critical() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    journal.set_db_faults(DbFaults {
        fail_outcome_commit: true,
        ..DbFaults::default()
    });
    journal.spool().set_faults(SpoolFaults {
        fail_slot_write: Some(0),
        ..SpoolFaults::default()
    });
    let error = journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ExternalJournalError::SystemIntegrity(_)),
        "unexpected error: {error:?}"
    );

    // The unresolved fact is retained in memory rather than silently dropped.
    let facts = journal.unresolved_facts();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].operation_id, ticket.operation_id);
    assert_eq!(facts[0].state, ExternalJournalState::Accepted);

    // All new external effects stop, and doctor goes critical.
    assert!(journal.integrity_failure().is_some());
    assert!(matches!(
        journal.ensure_dispatch_allowed().await,
        Err(ExternalJournalError::DispatchBlocked(_))
    ));
    let status = journal.status(T0 + 10).await.unwrap();
    assert!(status.is_critical());
    assert!(status.dispatch_blocked());
    assert!(
        status
            .render_lines()
            .iter()
            .any(|line| line.starts_with("integrity: FAILED"))
    );
}

#[tokio::test]
async fn external_journal_recovery_capsule_terminal_removal_waits_for_db_confirmation() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;
    let capsule_uuid = ticket.capsule_uuid();
    assert!(journal.spool().capsule_exists(capsule_uuid));

    let durability = journal
        .record_outcome(&mut ticket, ExternalJournalState::Rejected, T0 + 10)
        .await
        .unwrap();
    assert_eq!(durability, OutcomeDurability::Database);
    assert_eq!(
        env.db()
            .external_operation(ticket.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::Rejected
    );
    // Removed only after SQLite confirmed the terminal state.
    assert!(!journal.spool().capsule_exists(capsule_uuid));
    assert_eq!(
        env.db()
            .external_journal_capacity()
            .await
            .unwrap()
            .total_capsules(),
        0
    );
}

#[tokio::test]
async fn external_journal_recovery_capsule_orphans_and_foreign_entries_are_quarantined() {
    let env = Env::new();
    let journal = env.journal();
    let orphan = Uuid::new_v4();
    journal.spool().create_capsule(orphan).unwrap();
    std::fs::write(env.spool_root().join("capsules").join("stray.bin"), b"x").unwrap();

    let report = journal.recover(T0).await.unwrap();
    assert_eq!(report.foreign_quarantined, 1);
    assert_eq!(report.quarantined, 1);
    assert!(journal.spool().list_capsules().unwrap().is_empty());
    assert_eq!(journal.spool().list_quarantined().unwrap().len(), 2);
}

// ---- criterion 6: fault convergence -------------------------------------

#[tokio::test]
async fn external_journal_fault_key_rotation_retains_referenced_versions() {
    let env = Env::new();
    let operation_id = {
        let journal = env.journal();
        let mut ticket = dispatch(&journal, "k1").await;
        journal.set_db_faults(DbFaults {
            fail_outcome_commit: true,
            ..DbFaults::default()
        });
        journal
            .record_outcome(
                &mut ticket,
                ExternalJournalState::SubmissionUnknown,
                T0 + 10,
            )
            .await
            .unwrap();
        ticket.operation_id
    };

    // The ledger still references key version 1.
    assert_eq!(
        env.db()
            .external_journal_referenced_key_versions()
            .await
            .unwrap(),
        vec![1]
    );

    // Rotating without retaining version 1 quarantines rather than trusting.
    let rotated = env.journal_with_keys(SpoolKeyRing::for_test(&[(2, [0x22u8; 32])], 2).unwrap());
    let report = rotated.recover(T0 + 100).await.unwrap();
    assert_eq!(report.quarantined, 1);
    assert_eq!(report.imported, 0);

    // CORRECTED EXPECTATION (was `Dispatching`). Losing the key version means
    // the capsule cannot be authenticated, so the record has no evidence for a
    // post-`dispatching` outcome. The prompt requires that state to become
    // `submission_unknown`: the work is withheld and unresolved, never
    // presented as if it were still a pre-handoff transient. The old
    // expectation also hid the record from the 15m/24h unresolved reporting.
    let record = env
        .db()
        .external_operation(operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::SubmissionUnknown);
    assert!(record.state.is_unresolved());
    // No blind resubmission is authorised for it.
    assert!(!record.retry_permitted());
}

#[tokio::test]
async fn external_journal_fault_retained_key_version_imports_cleanly() {
    let env = Env::new();
    let operation_id = {
        let journal = env.journal();
        let mut ticket = dispatch(&journal, "k1").await;
        journal.set_db_faults(DbFaults {
            fail_outcome_commit: true,
            ..DbFaults::default()
        });
        journal
            .record_outcome(
                &mut ticket,
                ExternalJournalState::SubmissionUnknown,
                T0 + 10,
            )
            .await
            .unwrap();
        ticket.operation_id
    };

    let retained = env.journal_with_keys(
        SpoolKeyRing::for_test(&[(1, [0x11u8; 32]), (2, [0x22u8; 32])], 2).unwrap(),
    );
    let report = retained.recover(T0 + 100).await.unwrap();
    assert_eq!(report.imported, 1);
    assert_eq!(report.quarantined, 0);
    let record = env
        .db()
        .external_operation(operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::SubmissionUnknown);
    // Ambiguity is preserved, not resolved by a blind resubmission.
    assert!(!record.retry_permitted());
}

// ---- criterion 5: exactly once ------------------------------------------

#[tokio::test]
async fn external_journal_exactly_once_duplicate_prepare_reuses_the_operation() {
    let env = Env::new();
    let journal = env.journal();
    let projection = projection();
    let first = journal
        .prepare(&owner(), &key("k1"), &projection, T0)
        .await
        .unwrap();
    let second = journal
        .prepare(&owner(), &key("k1"), &projection, T0 + 5)
        .await
        .unwrap();
    assert_eq!(first.operation_id, second.operation_id);
    assert_eq!(second.version, 1);
}

#[tokio::test]
async fn external_journal_exactly_once_cancel_races_the_handoff() {
    let env = Env::new();
    let journal = env.journal();
    let ticket = dispatch(&journal, "k1").await;

    // The cancellation lands after the `dispatching` commit, so it can only
    // reach `cancellation_requested`.
    let cancelled = journal
        .request_cancellation(ticket.operation_id, T0 + 5)
        .await
        .unwrap();
    assert_eq!(cancelled.state, ExternalJournalState::CancellationRequested);
    assert_eq!(cancelled.cancellation_requested_at_wall_ms, Some(T0 + 5));
    assert!(journal.spool().capsule_exists(ticket.capsule_uuid()));

    // Provider evidence then chooses the authoritative outcome. Plain
    // `succeeded` is unreachable.
    let db = env.db();
    let error = db
        .transition_external_operation(
            cancelled.operation_id,
            cancelled.version,
            ExternalJournalState::Succeeded,
            T0 + 10,
        )
        .await
        .unwrap_err();
    // `cancellation_requested` has no `succeeded` edge at all, so the graph
    // refuses this before the cancellation guard is consulted. Both layers
    // reach the same verdict; assert the typed cause rather than the wording
    // of whichever layer happened to fire.
    let cause = cockpit_db::external_journal::illegal_transition_cause(&error)
        .expect("a refused edge must carry a typed legality cause");
    assert_eq!(cause.from, ExternalJournalState::CancellationRequested);
    assert_eq!(cause.to, ExternalJournalState::Succeeded);
    assert!(
        !ExternalJournalState::CancellationRequested
            .allows_transition_to(ExternalJournalState::Succeeded)
    );

    let done = db
        .transition_external_operation(
            cancelled.operation_id,
            cancelled.version,
            ExternalJournalState::CompletedAfterCancel,
            T0 + 11,
        )
        .await
        .unwrap();
    assert_eq!(
        done.record().state,
        ExternalJournalState::CompletedAfterCancel
    );
    let events = db
        .external_operation_events(cancelled.operation_id)
        .await
        .unwrap();
    assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
}

#[tokio::test]
async fn external_journal_exactly_once_session_tombstone_keeps_unresolved_work() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 5)
        .await
        .unwrap();

    let db = env.db();
    let unresolved = db
        .tombstone_external_journal_session(&owner(), T0 + 6)
        .await
        .unwrap();
    assert_eq!(unresolved, 1);
    assert!(
        db.external_journal_session_tombstoned(&owner())
            .await
            .unwrap()
    );
    // Resolution after deletion still commits exactly one terminal event and
    // never recreates session content.
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Succeeded, T0 + 7)
        .await
        .unwrap();
    let events = db
        .external_operation_events(ticket.operation_id)
        .await
        .unwrap();
    assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
}

// ---- criterion 4: age policy over the full stack ------------------------

#[tokio::test]
async fn external_journal_age_policy_expiry_releases_no_capsule() {
    let env = Env::new();
    let journal = env.journal();
    let projection = projection();
    let record = journal
        .prepare(&owner(), &key("k1"), &projection, 0)
        .await
        .unwrap();

    let expired = journal
        .expire_prepared(EXTERNAL_JOURNAL_PREPARED_TTL_MS + 1)
        .await
        .unwrap();
    assert_eq!(expired, vec![record.operation_id]);
    assert_eq!(
        env.db()
            .external_operation(record.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::Expired
    );
    assert!(journal.spool().list_capsules().unwrap().is_empty());
}

#[tokio::test]
async fn external_journal_age_policy_unresolved_work_is_never_age_deleted() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;
    journal
        .record_outcome(&mut ticket, ExternalJournalState::SubmissionUnknown, T0)
        .await
        .unwrap();

    let expired = journal
        .expire_prepared(T0 + EXTERNAL_JOURNAL_PREPARED_TTL_MS * 10)
        .await
        .unwrap();
    assert!(expired.is_empty());

    let status = journal
        .status(T0 + EXTERNAL_JOURNAL_PREPARED_TTL_MS)
        .await
        .unwrap();
    assert_eq!(status.age.unresolved, 1);
    assert_eq!(status.age.critical, 1);
    assert!(status.is_critical());
    assert!(journal.spool().capsule_exists(ticket.capsule_uuid()));
}

// ---- criterion 3/9: status surfaces exact counts ------------------------

#[tokio::test]
async fn external_journal_spool_limits_status_reports_exact_counts() {
    let env = Env::new();
    let journal = env.journal();
    let ticket = dispatch(&journal, "k1").await;

    let status = journal.status(T0).await.unwrap();
    assert_eq!(status.capacity.admission_capsules, 1);
    assert_eq!(status.capacity.admission_bytes, 65_536);
    assert_eq!(status.capacity.recovery_capsules, 0);
    assert_eq!(status.spool_allocated_bytes, 65_536);
    assert_eq!(status.quarantined_entries, 0);
    assert!(!status.dispatch_blocked());

    let lines = status.render_lines();
    assert!(lines.iter().any(|line| line.contains("1/3072 admission")));
    assert!(
        lines
            .iter()
            .any(|line| line.contains("0/1024 recovery reserve"))
    );
    assert!(lines.iter().any(|line| line.contains("1/4096 hard limit")));
    assert!(
        lines
            .iter()
            .any(|line| line.contains("65536/201326592 admission"))
    );
    assert!(lines.iter().any(|line| line == "admission: ok"));
    assert!(
        lines
            .iter()
            .any(|line| line == "quarantine: ok (0 entries)")
    );
    assert!(journal.spool().capsule_exists(ticket.capsule_uuid()));
}

// ---- criterion 7: redaction sentinels across every surface --------------

const SENTINELS: &[&str] = &[
    "SENTINEL-PROMPT-TEXT",
    "SENTINEL-TYPED-INPUT",
    "SENTINEL-BEARER-CREDENTIAL",
    "/sentinel/raw/path",
    "https://sentinel.example/asset?sig=SENTINEL",
    "x-sentinel-header",
];

fn assert_no_sentinels(label: &str, haystack: &[u8]) {
    for sentinel in SENTINELS {
        assert!(
            !haystack
                .windows(sentinel.len())
                .any(|window| window == sentinel.as_bytes()),
            "{sentinel} leaked into {label}"
        );
    }
}

#[tokio::test]
async fn external_journal_redaction_sentinels_absent_from_every_surface() {
    let env = Env::new();
    let journal = env.journal();

    // Build the operation from forbidden material: only digests survive.
    let projection = SanitizedProjection::new(OperationBody::Sidecar {
        sidecar_kind: super::projection::SafeToken::parse("transcode").unwrap(),
        request_digest: Digest::of(b"SENTINEL-PROMPT-TEXT /sentinel/raw/path"),
    });
    let record = journal
        .prepare(&owner(), &key("k1"), &projection, T0)
        .await
        .unwrap();
    let mut ticket = journal
        .begin_dispatch(record.operation_id, &projection, T0)
        .await
        .unwrap();
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 1)
        .await
        .unwrap();

    // Spool bytes.
    let capsule = std::fs::read(env.capsule_path(ticket.capsule_uuid())).unwrap();
    assert_no_sentinels("the capsule", &capsule);
    // The 32-byte HMAC key must not appear in the capsule either.
    let key_bytes = [0x11u8; 32];
    assert!(
        !capsule
            .windows(32)
            .any(|window| window == key_bytes.as_slice()),
        "spool key material leaked into the capsule"
    );

    // Status lines and doctor output.
    let status = journal.status(T0 + 1).await.unwrap();
    let rendered = status.render_lines().join("\n");
    assert_no_sentinels("status output", rendered.as_bytes());
    assert!(
        !rendered.contains("1111111111"),
        "key bytes leaked into status"
    );

    // Debug renderings used by logs and diagnostics.
    assert_no_sentinels("journal debug", format!("{journal:?}").as_bytes());
    assert_no_sentinels("ticket debug", format!("{ticket:?}").as_bytes());
    assert_no_sentinels("record debug", format!("{record:?}").as_bytes());
    assert_no_sentinels("status debug", format!("{status:?}").as_bytes());

    // SQLite file. Drop the journal's handle first so the checkpoint is not
    // racing another live connection.
    drop(journal);
    let db = env.db();
    db.write(|conn| {
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    })
    .await
    .unwrap();
    drop(db);
    assert_no_sentinels("the database file", &std::fs::read(env.db_path()).unwrap());
}

// ---- item 5: post-commit failures must not report zero dispatch ----------

#[tokio::test]
async fn external_journal_pre_dispatch_post_commit_fault_retains_the_capsule() {
    let env = Env::new();
    let journal = env.journal();
    let provider = FakeProvider::default();
    let projection = projection();
    let record = journal
        .prepare(&owner(), &key("k1"), &projection, T0)
        .await
        .unwrap();

    // The `dispatching` commit succeeds and only then does the call fail.
    journal.set_db_faults(DbFaults {
        fail_after_dispatching_commit: true,
        ..DbFaults::default()
    });
    let error = journal
        .begin_dispatch(record.operation_id, &projection, T0)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ExternalJournalError::Database(_)),
        "unexpected error: {error:?}"
    );
    // No ticket, so no provider call. But this is NOT zero dispatch.
    assert_eq!(provider.count(), 0);

    let after = env
        .db()
        .external_operation(record.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.state, ExternalJournalState::Dispatching);
    assert!(after.dispatch_may_have_started());
    // The capsule is now the fallback medium and must survive; the reservation
    // must not be rolled back and capacity must not be freed.
    assert_eq!(journal.spool().list_capsules().unwrap().len(), 1);
    assert_eq!(
        env.db()
            .external_journal_capacity()
            .await
            .unwrap()
            .total_capsules(),
        1,
        "a post-commit failure must not free the fallback medium"
    );

    // Recovery treats it as the ambiguous post-handoff record it is.
    journal.set_db_faults(DbFaults::default());
    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(report.converted, 1);
    assert_eq!(
        env.db()
            .external_operation(record.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::SubmissionUnknown
    );
}

#[tokio::test]
async fn external_journal_pre_dispatch_concurrent_holder_capsule_is_never_deleted() {
    let env = Env::new();
    let journal = env.journal();
    let projection = projection();
    let record = journal
        .prepare(&owner(), &key("k1"), &projection, T0)
        .await
        .unwrap();

    // A racing handle wins the dispatching commit and owns the capsule.
    let racer = env.journal();
    let ticket = racer
        .begin_dispatch(record.operation_id, &projection, T0)
        .await
        .unwrap();

    // The loser refuses before touching anything, and must not delete the
    // winner's live capsule or release its reservation.
    let error = journal
        .begin_dispatch(record.operation_id, &projection, T0)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ExternalJournalError::State(_)),
        "unexpected error: {error:?}"
    );
    assert!(journal.spool().capsule_exists(ticket.capsule_uuid()));
    assert_eq!(
        env.db()
            .external_journal_capacity()
            .await
            .unwrap()
            .total_capsules(),
        1
    );
}

// ---- item 2: a lost compare-and-set is never durable success -------------

#[tokio::test]
async fn external_journal_cancellation_fact_cas_race_retargets_success() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    // A cancellation lands between handoff and provider evidence, so the
    // ticket's version is stale by the time the outcome arrives.
    let cancelled = journal
        .request_cancellation(ticket.operation_id, T0 + 5)
        .await
        .unwrap();
    assert_eq!(cancelled.state, ExternalJournalState::CancellationRequested);

    // The provider reports plain success. That outcome must not be dropped and
    // must not be recorded as `succeeded`.
    let durability = journal
        .record_outcome(&mut ticket, ExternalJournalState::Succeeded, T0 + 10)
        .await
        .unwrap();
    assert_eq!(durability, OutcomeDurability::DatabaseAfterReconcile);
    assert!(durability.is_authoritative());

    let record = env
        .db()
        .external_operation(ticket.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::CompletedAfterCancel);
    assert_eq!(record.cancellation_requested_at_wall_ms, Some(T0 + 5));
    let events = env
        .db()
        .external_operation_events(ticket.operation_id)
        .await
        .unwrap();
    assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
}

#[tokio::test]
async fn external_journal_exactly_once_lost_cas_is_never_reported_durable() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    // Another writer takes the record terminal first.
    env.db()
        .transition_external_operation(
            ticket.operation_id,
            ticket.version(),
            ExternalJournalState::Rejected,
            T0 + 5,
        )
        .await
        .unwrap();

    let error = journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
        .await
        .unwrap_err();
    match error {
        ExternalJournalError::OutcomeConflict { requested, current } => {
            assert_eq!(requested, "accepted");
            assert_eq!(current, "rejected");
        }
        other => panic!("a lost CAS must surface as a conflict, got {other:?}"),
    }
    let events = env
        .db()
        .external_operation_events(ticket.operation_id)
        .await
        .unwrap();
    assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
}

// ---- item 4: consecutive fallbacks must not strand an outcome ------------

#[tokio::test]
async fn external_journal_recovery_capsule_chained_fallbacks_replay_in_order() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    // A real outage, so the pending-fallback drain cannot quietly import step
    // one and turn this into a single-step chain.
    journal.set_db_faults(DbFaults {
        db_offline: true,
        ..DbFaults::default()
    });
    // dispatching(v2) -> accepted(v3) -> succeeded(v4), all through the spool.
    assert_eq!(
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
            .await
            .unwrap(),
        OutcomeDurability::SpoolFallback
    );
    assert_eq!(
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Succeeded, T0 + 20)
            .await
            .unwrap(),
        OutcomeDurability::SpoolFallback
    );
    assert!(ticket.has_pending_fallback());

    // Recovery replays both versions in order. Importing only the highest
    // would ask for an illegal `dispatching -> succeeded` edge and strand the
    // terminal outcome.
    let journal = env.journal();
    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(report.imported, 2, "both steps must replay: {report:?}");
    assert_eq!(report.quarantined, 0);

    let record = env
        .db()
        .external_operation(ticket.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::Succeeded);
    let events = env
        .db()
        .external_operation_events(ticket.operation_id)
        .await
        .unwrap();
    assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
}

#[tokio::test]
async fn external_journal_recovery_capsule_illegal_fallback_chain_is_refused() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    journal.set_db_faults(DbFaults {
        fail_outcome_commit: true,
        ..DbFaults::default()
    });
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
        .await
        .unwrap();

    // `accepted -> expired` is not an edge. Writing it would overwrite the
    // `dispatching` slot and leave a chain recovery could never bridge, so the
    // outcome is refused and the fact is retained in memory instead.
    let error = journal
        .record_outcome(&mut ticket, ExternalJournalState::Expired, T0 + 20)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ExternalJournalError::FallbackChainBroken { .. }),
        "unexpected error: {error:?}"
    );
    assert_eq!(journal.unresolved_facts().len(), 1);
    assert!(journal.integrity_failure().is_some());
    // The accepted fallback is still intact on disk.
    assert_eq!(ticket.state(), ExternalJournalState::Accepted);
}

#[tokio::test]
async fn external_journal_exactly_once_pending_fallback_is_imported_before_the_next_outcome() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    journal.set_db_faults(DbFaults {
        fail_outcome_commit: true,
        ..DbFaults::default()
    });
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
        .await
        .unwrap();
    assert!(ticket.has_pending_fallback());

    // The database comes back. The next outcome must not silently conflict
    // against a version SQLite never saw.
    journal.set_db_faults(DbFaults::default());
    let durability = journal
        .record_outcome(&mut ticket, ExternalJournalState::Succeeded, T0 + 20)
        .await
        .unwrap();
    assert_eq!(durability, OutcomeDurability::DatabaseAfterReconcile);
    assert!(!ticket.has_pending_fallback());

    let record = env
        .db()
        .external_operation(ticket.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::Succeeded);
    let events = env
        .db()
        .external_operation_events(ticket.operation_id)
        .await
        .unwrap();
    // prepared, dispatching, accepted (imported), succeeded.
    assert_eq!(events.len(), 4);
    assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
}

// ---- item 6: a cancel race must not drain admission capacity -------------

#[tokio::test]
async fn external_journal_recovery_capsule_missing_medium_releases_the_reservation() {
    let env = Env::new();
    let journal = env.journal();
    let ticket = dispatch(&journal, "k1").await;

    // The capsule file disappears while the ledger row survives — the shape a
    // cancellation racing terminal cleanup leaves behind.
    std::fs::remove_file(env.capsule_path(ticket.capsule_uuid())).unwrap();
    assert_eq!(
        env.db()
            .external_journal_capacity()
            .await
            .unwrap()
            .total_capsules(),
        1
    );

    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(report.released_without_medium, 1);
    assert_eq!(report.converted, 1);
    assert_eq!(
        env.db()
            .external_journal_capacity()
            .await
            .unwrap()
            .total_capsules(),
        0,
        "a missing medium must not drain admission capacity permanently"
    );
    // The record itself is never lost: it becomes unresolved, not terminal.
    let record = env
        .db()
        .external_operation(ticket.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::SubmissionUnknown);
    assert!(record.state.is_unresolved());
}

// ---- item 15: genuinely concurrent recovery workers ----------------------

#[tokio::test]
async fn external_journal_exactly_once_concurrent_recovery_workers_commit_once() {
    let env = Env::new();
    let operation_id = {
        let journal = env.journal();
        let mut ticket = dispatch(&journal, "k1").await;
        journal.set_db_faults(DbFaults {
            fail_outcome_commit: true,
            ..DbFaults::default()
        });
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
            .await
            .unwrap();
        ticket.operation_id
    };

    // Two workers, two independent database and spool handles, run at once.
    let first = env.journal();
    let second = env.journal();
    let (left, right) = tokio::join!(first.recover(T0 + 100), second.recover(T0 + 100));
    let left = left.unwrap();
    let right = right.unwrap();

    // Exactly one of them commits the import; the other is idempotent.
    assert_eq!(
        left.imported + right.imported,
        1,
        "left={left:?} right={right:?}"
    );
    let record = env
        .db()
        .external_operation(operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::Accepted);
    assert_eq!(record.version, 3);

    // And exactly one event version exists per transition.
    let events = env
        .db()
        .external_operation_events(operation_id)
        .await
        .unwrap();
    let versions: Vec<_> = events.iter().map(|event| event.version).collect();
    assert_eq!(versions, vec![1, 2, 3]);
}

// ---- item 12: an insecure spool blocks dispatch and is never repaired ----

#[cfg(unix)]
#[tokio::test]
async fn external_journal_spool_security_insecure_spool_blocks_dispatch() {
    use std::os::unix::fs::PermissionsExt as _;

    let env = Env::new();
    let journal = env.journal();
    let _ticket = dispatch(&journal, "k1").await;

    std::fs::set_permissions(
        env.spool_root().join("capsules"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    // Recovery refuses and latches, rather than silently chmod-repairing.
    let error = journal.recover(T0 + 100).await.unwrap_err();
    assert!(
        matches!(error, ExternalJournalError::InsecurePermissions(_)),
        "unexpected error: {error:?}"
    );
    assert!(journal.integrity_failure().is_some());
    assert!(matches!(
        journal.ensure_dispatch_allowed().await,
        Err(ExternalJournalError::DispatchBlocked(_))
    ));

    // Reopening does not repair it either; the mode is still wrong on disk.
    assert!(Spool::open_at(&env.spool_root(), SpoolAccess::Create).is_err());
    let mode = std::fs::metadata(env.spool_root().join("capsules"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o755, "inspection must not repair permissions");
}

/// A genuine version gap must stay a gap. Importing an authentic v5 slot as
/// v3 would silently erase the intermediate fact that once existed — possibly
/// cancellation evidence — and make a lossy replay look contiguous.
#[tokio::test]
async fn external_journal_recovery_capsule_import_preserves_slot_versions() {
    let env = Env::new();
    let journal = env.journal();
    let ticket = dispatch(&journal, "k1").await;
    let keys = keys_v1();

    // Slot 0 asserts `accepted` at v5 while the database sits at v2: the
    // bridging v3/v4 facts no longer exist anywhere.
    let far = CapsuleSlot {
        slot_index: 0,
        operation_id: ticket.operation_id,
        journal_version: 5,
        key_version: 1,
        state: ExternalJournalState::Accepted,
        updated_at_wall_ms: T0 + 50,
        projection: projection().encode().unwrap(),
    };
    journal
        .spool()
        .write_slot(ticket.capsule_uuid(), 0, &far.encode(&keys).unwrap())
        .unwrap();

    let recovering = env.journal();
    let report = recovering.recover(T0 + 100).await.unwrap();
    assert_eq!(report.imported, 1, "{report:?}");
    assert_eq!(
        report.skipped_facts, 1,
        "a version gap must be recorded, not renumbered away: {report:?}"
    );

    let record = env
        .db()
        .external_operation(ticket.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.state, ExternalJournalState::Accepted);
    assert_eq!(
        record.version, 5,
        "the slot's own version must be preserved; renumbering to 3 would hide the gap"
    );
    let events = env
        .db()
        .external_operation_events(ticket.operation_id)
        .await
        .unwrap();
    assert_eq!(
        events.iter().map(|event| event.version).collect::<Vec<_>>(),
        vec![1, 2, 5],
        "the event log must show the jump rather than a fabricated v3"
    );
}

#[tokio::test]
async fn external_journal_spool_security_quarantine_never_clobbers_evidence() {
    let env = Env::new();
    let journal = env.journal();
    let spool = journal.spool();
    let capsule_uuid = Uuid::new_v4();
    spool.create_capsule(capsule_uuid).unwrap();
    spool.quarantine_capsule(capsule_uuid).unwrap();

    // The same name arrives again; the first quarantined copy must survive.
    spool.create_capsule(capsule_uuid).unwrap();
    spool.quarantine_capsule(capsule_uuid).unwrap();
    let quarantined = spool.list_quarantined().unwrap();
    assert_eq!(quarantined.len(), 2, "{quarantined:?}");
    assert!(quarantined.contains(&format!("{capsule_uuid}.v1")));
    assert!(quarantined.contains(&format!("{capsule_uuid}.v1.1")));
}

// ---- item 1: the ring reference must survive a restart -------------------

/// Restart shape with `secure_store_backed = true`: a real `SecureKeyActor`
/// over the fake native store, so the reserve→activate lifecycle and the
/// actor's startup reconcile both really run.
mod secure_store_restart {
    use super::*;
    use crate::external_journal::keys::ExternalJournalSpoolReconciler;
    use crate::secure_key::{SecureKeyActor, fake::FakeNativeStore};
    use std::sync::Arc;

    /// Start the actor the way production boot does.
    ///
    /// `start_with_store` blocks on the actor thread's readiness handshake, so
    /// it panics if called from a Tokio worker. `boot_with_db` spawns a
    /// short-lived plain std thread for exactly this reason; the test mirrors
    /// it rather than pretending the constructor is async-safe.
    async fn boot_actor(db: &Db, store: &FakeNativeStore) -> SecureKeyActor {
        let db = db.clone();
        let store = store.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("external-journal-test-secure-key-boot".into())
            .spawn(move || {
                let reconciler = Arc::new(ExternalJournalSpoolReconciler::new(db.clone()));
                let _ = tx.send(SecureKeyActor::start_with_store(
                    db,
                    Box::new(store),
                    reconciler,
                ));
            })
            .expect("spawn secure key boot thread");
        rx.await
            .expect("secure key boot channel")
            .expect("secure key actor")
    }

    /// Shut the actor down off the runtime.
    ///
    /// `SecureKeyActor::drop` blocks on the worker's shutdown reply, so
    /// letting it fall out of scope inside `#[tokio::test]` panics exactly the
    /// way constructing it there does.
    async fn shutdown_actor(actor: SecureKeyActor) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("external-journal-test-secure-key-shutdown".into())
            .spawn(move || {
                drop(actor);
                let _ = tx.send(());
            })
            .expect("spawn secure key shutdown thread");
        rx.await.expect("secure key shutdown channel");
    }

    #[tokio::test]
    async fn external_journal_spool_security_ring_reference_survives_restart() {
        let env = Env::new();
        let store = FakeNativeStore::new();
        let db_path = env.db_path();
        let spool_root = env.spool_root();

        // --- first boot: journal starts, nothing dispatched yet ---
        let (first_operation, first_actor) = {
            let db = Db::open(&db_path).unwrap();
            let actor = boot_actor(&db, &store).await;
            let (journal, _) =
                ExternalJournal::start_at(db.clone(), &spool_root, &actor.handle(), T0)
                    .await
                    .expect("first boot");
            assert!(journal.keys().secure_store_backed());
            // No capsule exists yet: this is exactly the window in which the
            // reference has zero ledger rows.
            assert_eq!(
                db.external_journal_referenced_key_versions().await.unwrap(),
                Vec::<i64>::new()
            );

            let projection = projection();
            let record = journal
                .prepare(&owner(), &key("k1"), &projection, T0)
                .await
                .unwrap();
            journal
                .begin_dispatch(record.operation_id, &projection, T0)
                .await
                .expect("first boot dispatch");
            (record.operation_id, actor)
        };
        // A real restart: the first actor is gone before the second starts.
        shutdown_actor(first_actor).await;

        // --- restart: a new actor runs startup_reconcile before the journal ---
        let db = Db::open(&db_path).unwrap();
        let actor = boot_actor(&db, &store).await;
        let (journal, report) =
            ExternalJournal::start_at(db.clone(), &spool_root, &actor.handle(), T0 + 1_000)
                .await
                .expect("restart boot must not be poisoned by a released reference");
        // The first operation was mid-flight and is now unresolved, not lost.
        assert_eq!(report.converted, 1);
        assert_eq!(
            db.external_operation(first_operation)
                .await
                .unwrap()
                .unwrap()
                .state,
            ExternalJournalState::SubmissionUnknown
        );

        // The load-bearing assertion: dispatch still works after the restart.
        // If the ring reference had been released as an orphaned reservation,
        // activation would fail here and every future dispatch with it.
        let projection = projection();
        let second = journal
            .prepare(&owner(), &key("k2"), &projection, T0 + 1_000)
            .await
            .unwrap();
        journal
            .begin_dispatch(second.operation_id, &projection, T0 + 1_000)
            .await
            .expect("dispatch must still work after a restart");
        shutdown_actor(actor).await;
    }

    #[tokio::test]
    async fn external_journal_spool_security_reconciler_holds_the_ring_with_no_capsules() {
        // The predicate that makes the restart above work: a reservable
        // version with zero capsule rows still has a consumer, because the
        // journal's ring owns it.
        let env = Env::new();
        let store = FakeNativeStore::new();
        let db = Db::open(&env.db_path()).unwrap();
        let actor = boot_actor(&db, &store).await;
        let (journal, _) =
            ExternalJournal::start_at(db.clone(), &env.spool_root(), &actor.handle(), T0)
                .await
                .unwrap();

        let version = i64::from(journal.keys().active_version());
        let reference =
            cockpit_db::external_journal::external_journal_spool_key_reference_id(version);
        let exists = db
            .read({
                let reference = reference.clone();
                move |conn| {
                    cockpit_db::external_journal::external_journal_spool_consumer_exists_conn(
                        conn, &reference,
                    )
                }
            })
            .await
            .unwrap();
        assert!(
            exists,
            "a reservable version the ring owns must never look orphaned"
        );
        shutdown_actor(actor).await;
    }
}

// ---- item 2: a concurrent dispatcher must never rewrite another's slots ---

#[tokio::test]
async fn external_journal_pre_dispatch_concurrent_dispatchers_do_not_rewrite_slots() {
    let env = Env::new();
    let winner = env.journal();
    let loser = env.journal();
    let projection = projection();
    let record = winner
        .prepare(&owner(), &key("k1"), &projection, T0)
        .await
        .unwrap();

    // Both dispatchers race for the same prepared record.
    let (left, right) = tokio::join!(
        winner.begin_dispatch(record.operation_id, &projection, T0),
        loser.begin_dispatch(record.operation_id, &projection, T0)
    );
    let (ticket, refused) = match (left, right) {
        (Ok(ticket), Err(error)) | (Err(error), Ok(ticket)) => (ticket, error),
        (Ok(_), Ok(_)) => panic!("two dispatchers must not both win"),
        (Err(a), Err(b)) => panic!("at least one must win: {a:?} / {b:?}"),
    };
    assert!(
        matches!(
            refused,
            ExternalJournalError::State(_) | ExternalJournalError::Spool(_)
        ),
        "unexpected refusal: {refused:?}"
    );

    // Exactly one capsule, one reservation, and the winner's slots intact.
    assert_eq!(
        winner.spool().list_capsules().unwrap(),
        vec![ticket.capsule_uuid()]
    );
    assert_eq!(
        env.db()
            .external_journal_capacity()
            .await
            .unwrap()
            .total_capsules(),
        1
    );
    let keys = keys_v1();
    let slot1 = CapsuleSlot::decode(
        &winner.spool().read_slot(ticket.capsule_uuid(), 1).unwrap(),
        record.operation_id,
        &keys,
    )
    .unwrap();
    assert_eq!(slot1.state, ExternalJournalState::Dispatching);
    assert_eq!(slot1.journal_version, 2);

    // And the winner's fallback evidence survives a later outcome.
    let mut ticket = ticket;
    winner.set_db_faults(DbFaults {
        db_offline: true,
        ..DbFaults::default()
    });
    winner
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
        .await
        .unwrap();
    let slot0 = CapsuleSlot::decode(
        &winner.spool().read_slot(ticket.capsule_uuid(), 0).unwrap(),
        record.operation_id,
        &keys,
    )
    .unwrap();
    assert_eq!(slot0.state, ExternalJournalState::Accepted);
}

#[tokio::test]
async fn external_journal_recovery_capsule_prepared_scaffolding_is_reclaimed() {
    // A capsule left by a crashed pre-dispatch attempt must not wedge the
    // operation: `prepared` proves no dispatch began, so it is reclaimed.
    let env = Env::new();
    let journal = env.journal();
    let projection = projection();
    let record = journal
        .prepare(&owner(), &key("k1"), &projection, T0)
        .await
        .unwrap();
    journal.set_db_faults(DbFaults {
        fail_dispatching_commit: true,
        ..DbFaults::default()
    });
    assert!(
        journal
            .begin_dispatch(record.operation_id, &projection, T0)
            .await
            .is_err()
    );
    // Simulate the crash shape: the ledger row survives without its file being
    // cleaned up, by re-reserving and re-creating the capsule directly.
    let capsule_uuid = Uuid::new_v4();
    env.db()
        .reserve_external_journal_capsule(
            record.operation_id,
            capsule_uuid,
            1,
            CapsulePartition::Admission,
            false,
            T0,
        )
        .await
        .unwrap();
    journal.spool().create_capsule(capsule_uuid).unwrap();

    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(report.reclaimed_prepared, 1);
    assert!(journal.spool().list_capsules().unwrap().is_empty());
    assert_eq!(
        env.db()
            .external_journal_capacity()
            .await
            .unwrap()
            .total_capsules(),
        0
    );

    // And the operation can be dispatched cleanly afterwards.
    journal.set_db_faults(DbFaults::default());
    journal
        .begin_dispatch(record.operation_id, &projection, T0 + 200)
        .await
        .expect("a reclaimed operation must be dispatchable");
}

// ---- item 3: authenticated evidence the DB cannot reach is an integrity fault

#[tokio::test]
async fn external_journal_recovery_capsule_unreachable_evidence_is_never_downgraded() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    journal.set_db_faults(DbFaults {
        db_offline: true,
        ..DbFaults::default()
    });
    // dispatching(v2) -> accepted(v3, slot 0) -> succeeded(v4, slot 1).
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
        .await
        .unwrap();
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Succeeded, T0 + 20)
        .await
        .unwrap();

    // Corrupt only the intermediate `accepted` slot. The authentic terminal
    // `succeeded` at v4 now has no legal path from the database's v2.
    let path = env.capsule_path(ticket.capsule_uuid());
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[100] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    let journal = env.journal();
    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(
        report.unreachable_evidence, 1,
        "a terminal outcome must never be silently discarded: {report:?}"
    );
    assert_eq!(report.converted, 0, "the record must not be downgraded");
    // Counted as unreachable evidence rather than a generic quarantine: the
    // two are disjoint so the report distinguishes "corrupt, nothing lost"
    // from "authenticated outcome the database cannot reach".
    assert_eq!(report.quarantined, 0, "{report:?}");
    // The capsule really moved; the counter is not the only evidence.
    assert!(journal.spool().list_capsules().unwrap().is_empty());
    assert_eq!(journal.spool().list_quarantined().unwrap().len(), 1);
    assert!(journal.integrity_failure().is_some());
    assert!(matches!(
        journal.ensure_dispatch_allowed().await,
        Err(ExternalJournalError::DispatchBlocked(_))
    ));
    // The record keeps its last authoritative state rather than being
    // downgraded to `submission_unknown` over the top of terminal evidence.
    assert_eq!(
        env.db()
            .external_operation(ticket.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::Dispatching
    );
}

// ---- item 4: legality rejections never reach the fallback medium ----------

#[tokio::test]
async fn external_journal_cancellation_fact_rejection_never_becomes_a_fallback() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    // Set the cancellation fact first, then let the provider's acceptance
    // bring the ticket back in step with the database. After this the ticket
    // version matches, so the next outcome is refused for *legality*, not for
    // a lost compare-and-set — which is the path that used to be misread as a
    // database outage.
    journal
        .request_cancellation(ticket.operation_id, T0 + 5)
        .await
        .unwrap();
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 6)
        .await
        .unwrap();
    let synced = env
        .db()
        .external_operation(ticket.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(synced.state, ExternalJournalState::Accepted);
    assert_eq!(
        synced.version,
        ticket.version(),
        "the ticket must be in step so the next refusal is a legality rejection"
    );

    // Prove the raw database call really rejects on legality here.
    let rejection = env
        .db()
        .transition_external_operation(
            ticket.operation_id,
            ticket.version(),
            ExternalJournalState::Succeeded,
            T0 + 9,
        )
        .await
        .unwrap_err();
    assert!(
        cockpit_db::external_journal::illegal_transition_cause(&rejection).is_some(),
        "expected a typed legality rejection, got {rejection:#}"
    );

    let capsule_uuid = ticket.capsule_uuid();
    let keys = keys_v1();
    let before: Vec<_> = (0..2)
        .map(|slot| journal.spool().read_slot(capsule_uuid, slot).unwrap())
        .collect();

    // The journal must retarget rather than fall back to the spool.
    let durability = journal
        .record_outcome(&mut ticket, ExternalJournalState::Succeeded, T0 + 10)
        .await
        .unwrap();
    assert_eq!(durability, OutcomeDurability::DatabaseAfterReconcile);
    assert_eq!(
        env.db()
            .external_operation(ticket.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::CompletedAfterCancel
    );

    // No `succeeded` slot was ever written. The capsule is gone because the
    // terminal state was confirmed, and neither pre-existing slot mutated.
    assert!(!journal.spool().capsule_exists(capsule_uuid));
    for bytes in before {
        if let Ok(decoded) = CapsuleSlot::decode(&bytes, ticket.operation_id, &keys) {
            assert_ne!(
                decoded.state,
                ExternalJournalState::Succeeded,
                "a rejected outcome must never become durable"
            );
        }
    }
    let events = env
        .db()
        .external_operation_events(ticket.operation_id)
        .await
        .unwrap();
    assert_eq!(events.iter().filter(|event| event.terminal).count(), 1);
}

// ---- item 5: a second outcome during a continuing outage is not lost ------

#[tokio::test]
async fn external_journal_recovery_capsule_second_outcome_during_outage_is_retained() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    // A real outage: reads fail too, so the pending-fallback drain takes its
    // true failure path rather than quietly succeeding.
    journal.set_db_faults(DbFaults {
        db_offline: true,
        ..DbFaults::default()
    });
    assert_eq!(
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
            .await
            .unwrap(),
        OutcomeDurability::SpoolFallback
    );
    // The second outcome must still land somewhere durable.
    assert_eq!(
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Succeeded, T0 + 20)
            .await
            .unwrap(),
        OutcomeDurability::SpoolFallback
    );
    assert_eq!(ticket.state(), ExternalJournalState::Succeeded);

    // Both steps are on disk and replay in order once the database returns.
    let journal = env.journal();
    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(report.imported, 2, "{report:?}");
    assert_eq!(
        env.db()
            .external_operation(ticket.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::Succeeded
    );
}

// ---- item 6: an unverifiable capsule is not a missing medium --------------

#[cfg(unix)]
#[tokio::test]
async fn external_journal_spool_security_unverifiable_capsule_quarantines_not_releases() {
    use std::os::unix::fs::PermissionsExt as _;

    let env = Env::new();
    let journal = env.journal();
    let ticket = dispatch(&journal, "k1").await;

    // The capsule exists but is world-writable: present, not trustworthy.
    std::fs::set_permissions(
        env.capsule_path(ticket.capsule_uuid()),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();

    let report = journal.recover(T0 + 100).await.unwrap();
    assert_eq!(report.quarantined, 1, "{report:?}");
    assert_eq!(
        report.released_without_medium, 0,
        "an unverifiable capsule must not be treated as a missing medium"
    );
    assert_eq!(report.converted, 0);
    // The hostile file was actually moved, not merely forgotten.
    assert!(journal.spool().list_capsules().unwrap().is_empty());
    assert_eq!(journal.spool().list_quarantined().unwrap().len(), 1);
    assert!(journal.integrity_failure().is_some());
    assert!(matches!(
        journal.ensure_dispatch_allowed().await,
        Err(ExternalJournalError::DispatchBlocked(_))
    ));
}

// ---- item 8: tombstones are bounded --------------------------------------

#[tokio::test]
async fn external_journal_age_policy_tombstones_are_pruned_when_nothing_is_unresolved() {
    use cockpit_db::external_journal::EXTERNAL_JOURNAL_TOMBSTONE_RETENTION_MS;

    let env = Env::new();
    let db = env.db();
    let journal = env.journal();

    // An old tombstone for a session with no unresolved work.
    db.tombstone_external_journal_session(&key("session-gone"), 0)
        .await
        .unwrap();
    // And one for a session that still has unresolved work.
    let mut ticket = dispatch(&journal, "k1").await;
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, 0)
        .await
        .unwrap();
    db.tombstone_external_journal_session(&owner(), 0)
        .await
        .unwrap();

    let now = EXTERNAL_JOURNAL_TOMBSTONE_RETENTION_MS + 1;
    let pruned = db.prune_external_journal_tombstones(now).await.unwrap();
    assert_eq!(pruned, 1);
    assert!(
        !db.external_journal_session_tombstoned(&key("session-gone"))
            .await
            .unwrap()
    );
    assert!(
        db.external_journal_session_tombstoned(&owner())
            .await
            .unwrap(),
        "a tombstone must survive while its session has unresolved work"
    );

    // Fresh tombstones are retained.
    db.tombstone_external_journal_session(&key("session-new"), now)
        .await
        .unwrap();
    assert_eq!(db.prune_external_journal_tombstones(now).await.unwrap(), 0);
}

// ---- item 1: the capsule holds at most two pending versions --------------

#[tokio::test]
async fn external_journal_recovery_capsule_three_outcome_outage_converges_without_quarantine() {
    // The exact scenario that used to produce a false corruption report:
    // three legal outcomes during one outage, zero corruption anywhere.
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    journal.set_db_faults(DbFaults {
        db_offline: true,
        ..DbFaults::default()
    });
    assert_eq!(
        journal
            .record_outcome(
                &mut ticket,
                ExternalJournalState::SubmissionUnknown,
                T0 + 10
            )
            .await
            .unwrap(),
        OutcomeDurability::SpoolFallback
    );
    assert_eq!(
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Reconciling, T0 + 20)
            .await
            .unwrap(),
        OutcomeDurability::SpoolFallback
    );

    // The third outcome cannot fit: writing it would overwrite the slot that
    // bridges from the database's committed version. It is refused and
    // retained, never written over the bridge.
    let error = journal
        .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 30)
        .await
        .unwrap_err();
    match error {
        ExternalJournalError::FallbackDepthExceeded { committed, pending } => {
            assert_eq!(committed, 2);
            assert_eq!(pending, 2);
        }
        other => panic!("expected a depth refusal, got {other:?}"),
    }
    let facts = journal.unresolved_facts();
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].state, ExternalJournalState::Accepted);

    // Recovery converges on the two durable facts with no quarantine and no
    // false "unreachable evidence" report.
    let recovering = env.journal();
    let report = recovering.recover(T0 + 100).await.unwrap();
    assert_eq!(report.imported, 2, "{report:?}");
    assert_eq!(report.quarantined, 0, "{report:?}");
    assert_eq!(report.unreachable_evidence, 0, "{report:?}");
    assert_eq!(report.skipped_facts, 0, "{report:?}");
    assert_eq!(
        env.db()
            .external_operation(ticket.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::Reconciling
    );
}

#[tokio::test]
async fn external_journal_recovery_capsule_fallback_depth_is_refused_not_overwritten() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;
    let keys = keys_v1();

    journal.set_db_faults(DbFaults {
        db_offline: true,
        ..DbFaults::default()
    });
    journal
        .record_outcome(
            &mut ticket,
            ExternalJournalState::SubmissionUnknown,
            T0 + 10,
        )
        .await
        .unwrap();
    journal
        .record_outcome(&mut ticket, ExternalJournalState::Reconciling, T0 + 20)
        .await
        .unwrap();
    let bridge_before = journal.spool().read_slot(ticket.capsule_uuid(), 0).unwrap();

    assert!(matches!(
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 30)
            .await,
        Err(ExternalJournalError::FallbackDepthExceeded { .. })
    ));

    // The bridging slot is byte-identical: the refusal happened before any
    // write, so the chain from the committed version is intact.
    assert_eq!(
        journal.spool().read_slot(ticket.capsule_uuid(), 0).unwrap(),
        bridge_before
    );
    let bridge = CapsuleSlot::decode(&bridge_before, ticket.operation_id, &keys).unwrap();
    assert_eq!(bridge.state, ExternalJournalState::SubmissionUnknown);
    assert_eq!(bridge.journal_version, 3);
    // The ticket did not advance past what is durable.
    assert_eq!(ticket.state(), ExternalJournalState::Reconciling);
    assert!(journal.integrity_failure().is_some());
}

// ---- item 2: reservation ownership is not capsule ownership --------------

/// Both interleavings of two dispatchers racing the same prepared record.
/// Whichever wins, the loser must leave the winner's ledger row and capsule
/// alone, or the winner ends up dispatched with no reservation.
async fn assert_dispatch_race_preserves_the_winner(swap_poll_order: bool) {
    let env = Env::new();
    let first = env.journal();
    let second = env.journal();
    let projection = projection();
    let record = first
        .prepare(&owner(), &key("k1"), &projection, T0)
        .await
        .unwrap();

    let (left, right) = if swap_poll_order {
        let (right, left) = tokio::join!(
            second.begin_dispatch(record.operation_id, &projection, T0),
            first.begin_dispatch(record.operation_id, &projection, T0)
        );
        (left, right)
    } else {
        tokio::join!(
            first.begin_dispatch(record.operation_id, &projection, T0),
            second.begin_dispatch(record.operation_id, &projection, T0)
        )
    };
    let ticket = match (left, right) {
        (Ok(ticket), Err(_)) | (Err(_), Ok(ticket)) => ticket,
        (Ok(_), Ok(_)) => panic!("two dispatchers must not both win"),
        (Err(a), Err(b)) => panic!("at least one must win: {a:?} / {b:?}"),
    };

    // The winner is dispatched AND still holds its reservation: without both,
    // its capsule would never be released and would be orphan-quarantined at
    // the next boot, blocking dispatch forever.
    let db = env.db();
    assert_eq!(
        db.external_operation(record.operation_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ExternalJournalState::Dispatching
    );
    let reservation = db
        .external_journal_capsule(record.operation_id)
        .await
        .unwrap()
        .expect("the dispatched operation must keep its ledger row");
    assert_eq!(reservation.capsule_uuid, ticket.capsule_uuid());
    assert_eq!(
        db.external_journal_capacity()
            .await
            .unwrap()
            .total_capsules(),
        1
    );
    assert!(first.spool().capsule_exists(ticket.capsule_uuid()));

    // And recovery agrees: nothing is orphaned, nothing is quarantined.
    let report = env.journal().recover(T0 + 100).await.unwrap();
    assert_eq!(report.quarantined, 0, "{report:?}");
    assert_eq!(report.released_without_medium, 0, "{report:?}");
}

#[tokio::test]
async fn external_journal_pre_dispatch_dispatch_race_preserves_the_winner_ledger_row() {
    assert_dispatch_race_preserves_the_winner(false).await;
}

#[tokio::test]
async fn external_journal_pre_dispatch_dispatch_race_preserves_the_winner_either_order() {
    assert_dispatch_race_preserves_the_winner(true).await;
}

// ---- item 4: the integrity latch reaches doctor across a restart ---------

#[tokio::test]
async fn external_journal_spool_security_integrity_latch_is_durable_for_doctor() {
    let env = Env::new();
    let journal = env.journal();
    let mut ticket = dispatch(&journal, "k1").await;

    // Both durable media fail after handoff.
    journal.set_db_faults(DbFaults {
        fail_outcome_commit: true,
        ..DbFaults::default()
    });
    journal.spool().set_faults(SpoolFaults {
        fail_slot_write: Some(0),
        ..SpoolFaults::default()
    });
    assert!(matches!(
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 10)
            .await,
        Err(ExternalJournalError::SystemIntegrity(_))
    ));

    // A fresh journal — a new process, holding none of that memory — must
    // still refuse dispatch and report critical.
    let restarted = env.journal();
    assert!(restarted.integrity_failure().is_none());
    assert!(matches!(
        restarted.ensure_dispatch_allowed().await,
        Err(ExternalJournalError::DispatchBlocked(_))
    ));

    // And the doctor path, which holds no journal instance at all, sees it.
    let status = super::collect_status(&env.db(), None, T0 + 20)
        .await
        .unwrap();
    assert!(status.integrity_failure.is_some());
    assert!(status.is_critical());
    assert!(
        status
            .render_lines()
            .iter()
            .any(|line| line.starts_with("integrity: FAILED"))
    );
}

// ---- item 5: a superseded key version can complete its retire cycle ------

#[tokio::test]
async fn external_journal_spool_security_superseded_key_version_can_release() {
    use cockpit_db::external_journal::external_journal_spool_key_version_in_use_conn;

    let env = Env::new();
    let db = env.db();
    // No namespace rows at all: nothing is active, so nothing is in use.
    let in_use = db
        .read(|conn| external_journal_spool_key_version_in_use_conn(conn, 7))
        .await
        .unwrap();
    assert!(
        !in_use,
        "a version with no capsules and no active claim must be releasable"
    );
}
