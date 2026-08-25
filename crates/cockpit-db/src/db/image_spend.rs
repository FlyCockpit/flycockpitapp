#![allow(clippy::items_after_test_module)]
//! Durable, exactly-once image-generation monetary reservations.

use anyhow::{Context, Result, bail, ensure};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use super::Db;
#[cfg(test)]
use super::external_journal::{ExternalJournalDigest, ExternalJournalToken};
use super::external_journal::{
    ExternalJournalRecord, ExternalJournalState, ExternalPrepareOutcome, ExternalTransitionOutcome,
    PrepareExternalOperation, prepare_external_operation_conn, transition_external_operation_conn,
};

fn sqlite_u64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| BudgetBlockReason::ArithmeticOverflow.into())
}

fn read_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn money_blob(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn read_money(value: Vec<u8>) -> rusqlite::Result<u64> {
    let bytes: [u8; 8] = value.try_into().map_err(|value: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("money value must be 8 bytes, got {}", value.len()),
            )
            .into(),
        )
    })?;
    Ok(u64::from_be_bytes(bytes))
}

/// Sum a money-valued (`BLOB` micro-USD) column selected by `sql` for a single
/// reservation, folding the values with overflow-checked addition. Lifted from
/// a let-bound closure to a module-level free function so the cockpit-db
/// blocking-boundary gate can statically resolve the call.
fn sum_reservation_money(
    conn: &rusqlite::Connection,
    reservation_id: &str,
    sql: &str,
) -> Result<u64> {
    let mut statement = conn.prepare(sql)?;
    let values = statement
        .query_map([reservation_id], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    values.into_iter().try_fold(0u64, |total, value| {
        total
            .checked_add(read_money(value)?)
            .ok_or_else(|| anyhow::Error::new(BudgetBlockReason::ArithmeticOverflow))
    })
}

pub(crate) fn prepare_reserved_image_spend_dispatch_conn(
    conn: &rusqlite::Connection,
    reservation_id: &str,
    attempt_id: &str,
    journal: &PrepareExternalOperation,
    at_ms: i64,
) -> Result<ExternalJournalRecord> {
    if journal.operation_kind.as_str() != "image_generation" {
        bail!("image spend dispatch requires image_generation journal kind");
    }
    let session_id: String = conn
        .query_row(
            "SELECT r.session_id FROM image_spend_attempts a JOIN image_spend_reservations r USING(reservation_id) WHERE a.reservation_id=?1 AND a.attempt_id=?2 AND r.state='reserved'",
            params![reservation_id, attempt_id],
            |row| row.get(0),
        )
        .context("image spend attempt is absent or no longer reserved")?;
    if journal.owner_session_id.as_str() != session_id {
        bail!("journal owner does not match the reserved image session");
    }
    let prepared = prepare_external_operation_conn(conn, journal, at_ms)?;
    let record = prepared.record();
    if let Some(existing_id) = conn
        .query_row(
            "SELECT external_operation_id FROM image_spend_attempt_dispatches WHERE reservation_id=?1 AND attempt_id=?2",
            params![reservation_id, attempt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        if existing_id != record.operation_id.to_string() {
            bail!("image spend attempt is already bound to another external operation");
        }
        return Ok(record.clone());
    }
    if matches!(&prepared, ExternalPrepareOutcome::Existing(_)) {
        bail!("existing external operation is not bound to this image spend attempt");
    }
    conn.execute(
        "INSERT INTO image_spend_attempt_dispatches(reservation_id,attempt_id,external_operation_id) VALUES(?1,?2,?3)",
        params![reservation_id, attempt_id, record.operation_id.to_string()],
    )?;
    Ok(record.clone())
}

pub(crate) fn finish_reserved_image_spend_dispatch_conn(
    conn: &rusqlite::Connection,
    reservation_id: &str,
    attempt_id: &str,
    operation_id: Uuid,
    expected_version: i64,
    evidence: ImageSpendDispatchEvidence,
    at_ms: i64,
) -> Result<ExternalTransitionOutcome> {
    let bound: Option<i64> = conn.query_row("SELECT 1 FROM image_spend_attempt_dispatches WHERE reservation_id=?1 AND attempt_id=?2 AND external_operation_id=?3",params![reservation_id,attempt_id,operation_id.to_string()],|row|row.get(0)).optional()?;
    if bound.is_none() {
        bail!("external operation is not bound to the image spend attempt");
    }
    let next = match evidence {
        ImageSpendDispatchEvidence::Accepted => ExternalJournalState::Accepted,
        ImageSpendDispatchEvidence::DefinitivelyRejected => ExternalJournalState::Rejected,
        ImageSpendDispatchEvidence::SubmissionUnknown => ExternalJournalState::SubmissionUnknown,
    };
    let outcome =
        transition_external_operation_conn(conn, operation_id, expected_version, next, at_ms)?;
    if outcome.record().state == ExternalJournalState::Rejected {
        let unrejected:i64=conn.query_row("SELECT COUNT(*) FROM image_spend_attempts a LEFT JOIN image_spend_attempt_dispatches d USING(reservation_id,attempt_id) LEFT JOIN external_journal_operations o ON o.operation_id=d.external_operation_id WHERE a.reservation_id=?1 AND COALESCE(o.state,'')<>'rejected'",[reservation_id],|row|row.get(0))?;
        if unrejected == 0 {
            let changed=conn.execute("UPDATE image_spend_reservations SET state='released',release_proof_identity=?2,released_at_ms=?3 WHERE reservation_id=?1 AND state='reserved'",params![reservation_id,operation_id.to_string(),at_ms])?;
            if changed != 0 {
                conn.execute("UPDATE image_spend_scope_usage SET reserved_usd_micros=charged_usd_micros WHERE reservation_id=?1",[reservation_id])?;
            }
        }
    }
    Ok(outcome)
}

pub(crate) fn settle_reconciled_image_spend_dispatch_conn(
    conn: &rusqlite::Connection,
    operation_id: Uuid,
    at_ms: i64,
) -> Result<()> {
    let reservation_id: String = conn.query_row(
        "SELECT reservation_id FROM image_spend_attempt_dispatches WHERE external_operation_id=?1",
        [operation_id.to_string()],
        |row| row.get(0),
    )?;
    let journal_state: String = conn.query_row(
        "SELECT state FROM external_journal_operations WHERE operation_id=?1",
        [operation_id.to_string()],
        |row| row.get(0),
    )?;
    ensure!(
        matches!(
            journal_state.as_str(),
            "accepted" | "rejected" | "cancelled" | "failed"
        ),
        "reconciled spend lacks a terminal provider outcome"
    );
    if matches!(journal_state.as_str(), "rejected" | "cancelled") {
        let unresolved: i64 = conn.query_row("SELECT COUNT(*) FROM image_spend_attempts a LEFT JOIN image_spend_attempt_dispatches d USING(reservation_id,attempt_id) LEFT JOIN external_journal_operations o ON o.operation_id=d.external_operation_id WHERE a.reservation_id=?1 AND COALESCE(o.state,'') NOT IN ('rejected','cancelled')",[&reservation_id],|row|row.get(0))?;
        if unresolved == 0 {
            let changed=conn.execute("UPDATE image_spend_reservations SET state='released',release_proof_identity=?2,released_at_ms=?3 WHERE reservation_id=?1 AND state='reserved'",params![reservation_id,operation_id.to_string(),at_ms])?;
            if changed != 0 {
                conn.execute("UPDATE image_spend_scope_usage SET reserved_usd_micros=charged_usd_micros WHERE reservation_id=?1",[reservation_id])?;
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetPolicy {
    #[default]
    Unconfigured,
    Finite {
        usd_micros: u64,
    },
    Unlimited,
}

/// Provider-neutral handoff result recorded immediately after a paid image
/// attempt returns. `SubmissionUnknown` deliberately retains the full hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageSpendDispatchEvidence {
    Accepted,
    DefinitivelyRejected,
    SubmissionUnknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finite(limit: u64) -> ImageSpendSettings {
        ImageSpendSettings {
            request: BudgetPolicy::Finite { usd_micros: limit },
            session: BudgetPolicy::Finite { usd_micros: limit },
            project: BudgetPolicy::Finite { usd_micros: limit },
            project_epoch: Some(ProjectEpochPolicy::CalendarMonth {
                time_zone: "UTC".into(),
            }),
        }
    }

    fn keys(plan: &str) -> SpendScopeKeys {
        SpendScopeKeys {
            plan_digest: plan.into(),
            session_id: SessionId::new("session").unwrap(),
            project_key: ProjectKey::new("project").unwrap(),
        }
    }

    #[tokio::test]
    async fn image_spend_requires_explicit_policy() {
        let db = Db::open_in_memory().unwrap();
        assert!(
            db.reserve_image_spend(
                "r".into(),
                keys("p"),
                vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: Some(1)
                }],
                1,
                0
            )
            .await
            .is_err()
        );
        let invalid = ImageSpendSettings::default();
        assert!(
            db.save_image_spend_policy("project".into(), invalid, None, 0)
                .await
                .is_err()
        );
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        db.reserve_image_spend(
            "r".into(),
            keys("p"),
            vec![AttemptMaximum {
                attempt_id: "a".into(),
                usd_micros: Some(1),
            }],
            1,
            0,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn image_spend_budget_atomic() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        let first = db.reserve_image_spend(
            "r1".into(),
            keys("p1"),
            vec![AttemptMaximum {
                attempt_id: "a1".into(),
                usd_micros: Some(6),
            }],
            1,
            0,
        );
        let second = db.reserve_image_spend(
            "r2".into(),
            keys("p2"),
            vec![AttemptMaximum {
                attempt_id: "a2".into(),
                usd_micros: Some(6),
            }],
            1,
            0,
        );
        let (first, second) = tokio::join!(first, second);
        assert_ne!(first.is_ok(), second.is_ok());
        assert!(
            db.reserve_image_spend(
                "overflow".into(),
                keys("p3"),
                vec![
                    AttemptMaximum {
                        attempt_id: "x".into(),
                        usd_micros: Some(u64::MAX)
                    },
                    AttemptMaximum {
                        attempt_id: "y".into(),
                        usd_micros: Some(1)
                    }
                ],
                1,
                0
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn paid_dispatch_requires_journal_evidence_before_release() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        db.reserve_image_spend(
            "dispatch".into(),
            keys("plan"),
            vec![AttemptMaximum {
                attempt_id: "attempt".into(),
                usd_micros: Some(5),
            }],
            1,
            0,
        )
        .await
        .unwrap();
        let prepared = db
            .prepare_image_spend_dispatch(
                "dispatch".into(),
                "attempt".into(),
                PrepareExternalOperation {
                    operation_kind: ExternalJournalToken::parse("image_generation").unwrap(),
                    owner_session_id: ExternalJournalToken::parse("session").unwrap(),
                    idempotency_key: ExternalJournalToken::parse("attempt-key").unwrap(),
                    payload_digest: ExternalJournalDigest::of(b"sanitized projection"),
                    payload_len: 20,
                    provider_idempotency: None,
                },
                1,
            )
            .await
            .unwrap();
        let dispatching = db
            .begin_image_spend_dispatch(
                "dispatch".into(),
                "attempt".into(),
                prepared.operation_id,
                prepared.version,
                2,
            )
            .await
            .unwrap();
        let unknown = db
            .finish_image_spend_dispatch(
                "dispatch".into(),
                "attempt".into(),
                prepared.operation_id,
                dispatching.record().version,
                ImageSpendDispatchEvidence::SubmissionUnknown,
                3,
            )
            .await
            .unwrap();
        assert_eq!(
            unknown.record().state,
            ExternalJournalState::SubmissionUnknown
        );
        assert_eq!(
            db.image_spend_diagnostic("dispatch".into())
                .await
                .unwrap()
                .unwrap()
                .state,
            "reserved"
        );
    }

    #[tokio::test]
    async fn reservation_and_journal_prepare_commit_or_rollback_together() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        let result = db
            .reserve_and_prepare_image_spend(ReserveAndPrepareImageSpend {
                reservation_id: "atomic".into(),
                keys: keys("plan"),
                attempts: vec![AttemptMaximum {
                    attempt_id: "attempt".into(),
                    usd_micros: Some(1),
                }],
                expected_policy_version: 1,
                attempt_id: "attempt".into(),
                journal: PrepareExternalOperation {
                    operation_kind: ExternalJournalToken::parse("image_generation").unwrap(),
                    owner_session_id: ExternalJournalToken::parse("wrong-session").unwrap(),
                    idempotency_key: ExternalJournalToken::parse("atomic-key").unwrap(),
                    payload_digest: ExternalJournalDigest::of(b"projection"),
                    payload_len: 10,
                    provider_idempotency: None,
                },
                created_at_ms: 0,
            })
            .await;
        assert!(result.is_err());
        assert!(
            db.image_spend_diagnostic("atomic".into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.external_operation_by_identity(
                &ExternalJournalToken::parse("image_generation").unwrap(),
                &ExternalJournalToken::parse("wrong-session").unwrap(),
                &ExternalJournalToken::parse("atomic-key").unwrap(),
            )
            .await
            .unwrap()
            .is_none()
        );
    }

    #[tokio::test]
    async fn calendar_and_rolling_epochs_advance_from_reservation_clock() {
        for (project, settings, rollover_ms) in [
            ("calendar", finite(100), 2_700_000_000),
            (
                "rolling",
                ImageSpendSettings {
                    project_epoch: Some(ProjectEpochPolicy::Rolling {
                        duration_seconds: 86_400,
                    }),
                    ..finite(100)
                },
                86_400_000,
            ),
        ] {
            let db = Db::open_in_memory().unwrap();
            db.save_image_spend_policy(project.into(), settings, None, 0)
                .await
                .unwrap();
            let mut scope = keys("first");
            scope.project_key = ProjectKey::new(project).unwrap();
            db.reserve_image_spend(
                "first".into(),
                scope,
                vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: Some(1),
                }],
                1,
                0,
            )
            .await
            .unwrap();
            let mut scope = keys("second");
            scope.project_key = ProjectKey::new(project).unwrap();
            db.reserve_image_spend(
                "second".into(),
                scope,
                vec![AttemptMaximum {
                    attempt_id: "b".into(),
                    usd_micros: Some(1),
                }],
                1,
                rollover_ms,
            )
            .await
            .unwrap();
            assert_eq!(
                db.image_spend_diagnostic("second".into())
                    .await
                    .unwrap()
                    .unwrap()
                    .epoch_sequence,
                2
            );
        }
    }

    #[tokio::test]
    async fn concurrent_epoch_rollover_cas_advances_once() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(100), None, 0)
            .await
            .unwrap();
        db.reserve_image_spend(
            "race-seed".into(),
            keys("race-seed"),
            vec![AttemptMaximum {
                attempt_id: "seed".into(),
                usd_micros: Some(1),
            }],
            1,
            0,
        )
        .await
        .unwrap();
        let first = db.reserve_image_spend(
            "race-a".into(),
            keys("race-a"),
            vec![AttemptMaximum {
                attempt_id: "a".into(),
                usd_micros: Some(1),
            }],
            1,
            2_700_000_000,
        );
        let second = db.reserve_image_spend(
            "race-b".into(),
            keys("race-b"),
            vec![AttemptMaximum {
                attempt_id: "b".into(),
                usd_micros: Some(1),
            }],
            1,
            2_700_000_000,
        );
        let (first, second) = tokio::join!(first, second);
        first.unwrap();
        second.unwrap();
        assert_eq!(
            db.image_spend_diagnostic("race-a".into())
                .await
                .unwrap()
                .unwrap()
                .epoch_sequence,
            2
        );
        assert_eq!(
            db.image_spend_diagnostic("race-b".into())
                .await
                .unwrap()
                .unwrap()
                .epoch_sequence,
            2
        );
    }

    #[tokio::test]
    async fn journal_fault_rolls_back_epoch_head_advance() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        let failed = db
            .reserve_and_prepare_image_spend(ReserveAndPrepareImageSpend {
                reservation_id: "future".into(),
                keys: keys("future"),
                attempts: vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: Some(1),
                }],
                expected_policy_version: 1,
                attempt_id: "a".into(),
                journal: PrepareExternalOperation {
                    operation_kind: ExternalJournalToken::parse("image_generation").unwrap(),
                    owner_session_id: ExternalJournalToken::parse("wrong").unwrap(),
                    idempotency_key: ExternalJournalToken::parse("future-key").unwrap(),
                    payload_digest: ExternalJournalDigest::of(b"p"),
                    payload_len: 1,
                    provider_idempotency: None,
                },
                created_at_ms: 2_700_000_000,
            })
            .await;
        assert!(failed.is_err());
        db.reserve_image_spend(
            "present".into(),
            keys("present"),
            vec![AttemptMaximum {
                attempt_id: "b".into(),
                usd_micros: Some(1),
            }],
            1,
            0,
        )
        .await
        .unwrap();
        assert_eq!(
            db.image_spend_diagnostic("present".into())
                .await
                .unwrap()
                .unwrap()
                .epoch_sequence,
            1
        );
    }

    #[tokio::test]
    async fn unknown_requires_all_unlimited_and_late_cost_charges_once() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        assert!(
            db.reserve_image_spend(
                "unknown".into(),
                keys("p"),
                vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: None
                }],
                1,
                0
            )
            .await
            .is_err()
        );
        let unlimited = ImageSpendSettings {
            request: BudgetPolicy::Unlimited,
            session: BudgetPolicy::Unlimited,
            project: BudgetPolicy::Unlimited,
            project_epoch: None,
        };
        db.save_image_spend_policy("project".into(), unlimited, Some(1), 1)
            .await
            .unwrap();
        let reservation = db
            .reserve_image_spend(
                "unknown".into(),
                keys("p"),
                vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: None,
                }],
                2,
                0,
            )
            .await
            .unwrap();
        assert!(reservation.cost_unknown);
        assert!(
            db.cancel_image_spend_before_dispatch("unknown".into(), 2)
                .await
                .unwrap()
        );
        assert!(
            db.reconcile_image_spend(
                "unknown".into(),
                "a".into(),
                "bill".into(),
                5,
                "evidence".into(),
                3
            )
            .await
            .unwrap()
        );
        assert!(
            !db.reconcile_image_spend(
                "unknown".into(),
                "a".into(),
                "bill".into(),
                5,
                "evidence".into(),
                3
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn policy_versions_preserve_original_epoch_attribution() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        db.reserve_image_spend(
            "old".into(),
            keys("old-plan"),
            vec![AttemptMaximum {
                attempt_id: "a".into(),
                usd_micros: Some(5),
            }],
            1,
            0,
        )
        .await
        .unwrap();
        let mut changed = finite(10);
        changed.project_epoch = Some(ProjectEpochPolicy::Rolling {
            duration_seconds: 86_400,
        });
        db.save_image_spend_policy("project".into(), changed, Some(1), 1)
            .await
            .unwrap();
        assert!(
            db.reserve_image_spend(
                "stale".into(),
                keys("stale"),
                vec![AttemptMaximum {
                    attempt_id: "b".into(),
                    usd_micros: Some(1)
                }],
                1,
                1
            )
            .await
            .is_err()
        );
        let old = db
            .image_spend_diagnostic("old".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                old.policy_version,
                old.epoch_policy_version,
                old.epoch_sequence
            ),
            (1, 1, 1)
        );
    }

    #[tokio::test]
    async fn overage_creates_debt_and_release_late_cost_does_not_resurrect() {
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(20), None, 0)
            .await
            .unwrap();
        db.reserve_image_spend(
            "over".into(),
            keys("over-plan"),
            vec![AttemptMaximum {
                attempt_id: "a".into(),
                usd_micros: Some(5),
            }],
            1,
            0,
        )
        .await
        .unwrap();
        db.reconcile_image_spend(
            "over".into(),
            "a".into(),
            "cost".into(),
            7,
            "normalized".into(),
            1,
        )
        .await
        .unwrap();
        let over = db
            .image_spend_diagnostic("over".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                over.state.as_str(),
                over.charged_usd_micros,
                over.debt_usd_micros
            ),
            ("budget_violation", 7, 2)
        );
        assert!(
            db.reserve_image_spend(
                "blocked".into(),
                keys("other"),
                vec![AttemptMaximum {
                    attempt_id: "b".into(),
                    usd_micros: Some(1)
                }],
                1,
                2
            )
            .await
            .is_err()
        );
        assert!(
            db.resolve_image_spend_debt("over".into(), "reviewed".into(), 3)
                .await
                .unwrap()
        );

        db.reserve_image_spend(
            "released".into(),
            keys("release-plan"),
            vec![
                AttemptMaximum {
                    attempt_id: "c".into(),
                    usd_micros: Some(4),
                },
                AttemptMaximum {
                    attempt_id: "d".into(),
                    usd_micros: Some(4),
                },
            ],
            1,
            4,
        )
        .await
        .unwrap();
        db.cancel_image_spend_before_dispatch("released".into(), 5)
            .await
            .unwrap();
        db.reconcile_image_spend(
            "released".into(),
            "c".into(),
            "late".into(),
            3,
            "normalized-late".into(),
            6,
        )
        .await
        .unwrap();
        let released = db
            .image_spend_diagnostic("released".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (released.state.as_str(), released.charged_usd_micros),
            ("reconciled", 3)
        );
    }

    #[test]
    fn calendar_epoch_rejects_non_iana_zone_and_derives_membership() {
        let invalid = ProjectEpochPolicy::CalendarMonth {
            time_zone: "Not/AZone".into(),
        };
        assert_eq!(
            invalid.validate(),
            Err(BudgetBlockReason::InvalidProjectEpoch)
        );
        let valid = ProjectEpochPolicy::CalendarMonth {
            time_zone: "America/Chicago".into(),
        };
        let epoch = valid.resolve_epoch(1_775_000_000_000, None).unwrap();
        assert_eq!(epoch.membership_key, "2026-03@America/Chicago");

        // 2026-03-08 01:00 CST and 04:00 CDT bracket Chicago's spring
        // transition while remaining in the same local calendar month.
        let before_dst = valid.resolve_epoch(1_772_953_200_000, None).unwrap();
        let after_dst = valid.resolve_epoch(1_772_960_400_000, None).unwrap();
        assert_eq!(before_dst.membership_key, after_dst.membership_key);
    }

    #[test]
    fn rolling_epoch_uses_saved_anchor_and_rejects_clock_rollback() {
        // The anchor is a server-owned input to resolution, not a field of the
        // user-constructible policy type.
        let rolling = ProjectEpochPolicy::Rolling {
            duration_seconds: 86_400,
        };
        let anchor = SavedInstant {
            unix_ms: 1_000,
            monotonic_sequence: 7,
        };
        assert_eq!(
            rolling
                .resolve_epoch(86_401_000, Some(&anchor))
                .unwrap()
                .membership_key,
            "rolling:8"
        );
        assert_eq!(
            rolling.resolve_epoch(999, Some(&anchor)),
            Err(BudgetBlockReason::InvalidProjectEpoch)
        );
        // A rolling policy with no server anchor fails closed.
        assert_eq!(
            rolling.resolve_epoch(86_401_000, None),
            Err(BudgetBlockReason::InvalidProjectEpoch)
        );
    }

    #[tokio::test]
    async fn cancellation_and_epoch_authority_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spend.db");
        {
            let db = Db::open(&path).unwrap();
            db.save_image_spend_policy("project".into(), finite(10), None, 0)
                .await
                .unwrap();
            db.reserve_image_spend(
                "cancelled".into(),
                keys("plan"),
                vec![AttemptMaximum {
                    attempt_id: "attempt".into(),
                    usd_micros: Some(2),
                }],
                1,
                0,
            )
            .await
            .unwrap();
            db.cancel_image_spend_before_dispatch("cancelled".into(), 1)
                .await
                .unwrap();
        }
        let reopened = Db::open(&path).unwrap();
        let policy = reopened
            .current_image_spend_policy("project".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.epoch_sequence, Some(1));
        assert_eq!(
            reopened
                .image_spend_diagnostic("cancelled".into())
                .await
                .unwrap()
                .unwrap()
                .state,
            "released"
        );
    }

    #[tokio::test]
    async fn finite_policy_preserves_full_u64_micros() {
        let db = Db::open_in_memory().unwrap();
        let settings = finite(u64::MAX);
        db.save_image_spend_policy("project".into(), settings, None, 0)
            .await
            .unwrap();
        let reserved = db
            .reserve_image_spend(
                "u64".into(),
                keys("u64-plan"),
                vec![AttemptMaximum {
                    attempt_id: "a".into(),
                    usd_micros: Some(u64::MAX),
                }],
                1,
                0,
            )
            .await
            .unwrap();
        assert_eq!(reserved.reserved_usd_micros, Some(u64::MAX));
    }

    #[tokio::test]
    async fn rolling_epoch_anchor_not_user_constructible() {
        // The `Rolling` variant has no `anchor` field, so an anchor is
        // unrepresentable as a user input (compile-forced). The server stamps
        // an effective anchor at save; a same-duration re-save cannot move it
        // and does not bump `epoch_policy_version`, while a duration change (or
        // Calendar<->Rolling) does. This proves an "anchor-only change" is a
        // no-op, so a future refactor that reintroduced a user anchor field
        // would fail here.
        let db = Db::open_in_memory().unwrap();
        let mut settings = finite(10);
        settings.project_epoch = Some(ProjectEpochPolicy::Rolling {
            duration_seconds: 86_400,
        });
        db.save_image_spend_policy("project".into(), settings.clone(), None, 10)
            .await
            .unwrap();
        let first = db
            .current_image_spend_policy("project".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.epoch_policy_version, 1);
        assert_eq!(
            first.effective_rolling_anchor,
            Some(SavedInstant {
                unix_ms: 10,
                monotonic_sequence: 1,
            })
        );

        // Same-duration Rolling->Rolling save at a DIFFERENT saved_at_ms: the
        // only thing that could differ is the anchor, and it must not move; the
        // epoch policy version must not bump.
        db.save_image_spend_policy("project".into(), settings.clone(), Some(1), 999)
            .await
            .unwrap();
        let unchanged = db
            .current_image_spend_policy("project".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.epoch_policy_version, 1);
        assert_eq!(
            unchanged.effective_rolling_anchor,
            first.effective_rolling_anchor
        );

        // A duration change is a real epoch-policy change: version bumps and a
        // fresh anchor is stamped from the server clock.
        settings.project_epoch = Some(ProjectEpochPolicy::Rolling {
            duration_seconds: 172_800,
        });
        db.save_image_spend_policy("project".into(), settings, Some(2), 20)
            .await
            .unwrap();
        let second = db
            .current_image_spend_policy("project".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.epoch_policy_version, 2);
        assert_eq!(
            second.effective_rolling_anchor,
            Some(SavedInstant {
                unix_ms: 20,
                monotonic_sequence: 2,
            })
        );
        assert_eq!(second.epoch_sequence, None);

        // Calendar<->Rolling is also a real change: version bumps and the
        // rolling anchor is cleared for a calendar policy.
        db.save_image_spend_policy("project".into(), finite(10), Some(3), 30)
            .await
            .unwrap();
        let calendar = db
            .current_image_spend_policy("project".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(calendar.epoch_policy_version, 3);
        assert_eq!(calendar.effective_rolling_anchor, None);
    }

    #[tokio::test]
    async fn spend_scope_keys_reject_empty_identity() {
        // Empty or whitespace-padded identities are rejected at the real
        // constructor funnel, so an empty scope key is unrepresentable and can
        // never reach the reservation SQL.
        assert_eq!(
            ProjectKey::new(""),
            Err(SpendScopeKeyError::EmptyProjectKey)
        );
        assert_eq!(
            ProjectKey::new("   "),
            Err(SpendScopeKeyError::EmptyProjectKey)
        );
        assert_eq!(
            ProjectKey::new(" pad "),
            Err(SpendScopeKeyError::EmptyProjectKey)
        );
        assert_eq!(SessionId::new(""), Err(SpendScopeKeyError::EmptySessionId));
        assert_eq!(
            SessionId::new("\t"),
            Err(SpendScopeKeyError::EmptySessionId)
        );
        assert_eq!(ProjectKey::new("project").unwrap().as_str(), "project");
        assert_eq!(SessionId::new("session").unwrap().as_str(), "session");

        // The reserve path only accepts these validated keys, so it exercises
        // them end-to-end.
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy("project".into(), finite(10), None, 0)
            .await
            .unwrap();
        db.reserve_image_spend(
            "typed".into(),
            SpendScopeKeys {
                plan_digest: "plan".into(),
                session_id: SessionId::new("session").unwrap(),
                project_key: ProjectKey::new("project").unwrap(),
            },
            vec![AttemptMaximum {
                attempt_id: "a".into(),
                usd_micros: Some(1),
            }],
            1,
            0,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn project_debt_is_global_used_is_epoch_scoped() {
        // A prior epoch that leaves unresolved debt on the project scope key
        // keeps blocking a NEW epoch (debt is global across epochs), even though
        // per-epoch `used` accounting for the new epoch starts clean. This
        // encodes the intentional asymmetry documented at the reservation gate;
        // if a future change epoch-filtered debt, the new-epoch reservation
        // below would wrongly succeed and fail this test.
        let db = Db::open_in_memory().unwrap();
        // Only the PROJECT scope is finite (request/session unlimited), so the
        // asymmetry under test is isolated to the project scope key. Rolling
        // window so a later reservation clock lands in a new epoch.
        let settings = ImageSpendSettings {
            request: BudgetPolicy::Unlimited,
            session: BudgetPolicy::Unlimited,
            project: BudgetPolicy::Finite { usd_micros: 20 },
            project_epoch: Some(ProjectEpochPolicy::Rolling {
                duration_seconds: 86_400,
            }),
        };
        db.save_image_spend_policy("project".into(), settings, None, 0)
            .await
            .unwrap();

        // Epoch 1: reserve then reconcile an overage, creating project-scope debt.
        db.reserve_image_spend(
            "epoch1".into(),
            keys("plan-1"),
            vec![AttemptMaximum {
                attempt_id: "a".into(),
                usd_micros: Some(5),
            }],
            1,
            0,
        )
        .await
        .unwrap();
        db.reconcile_image_spend(
            "epoch1".into(),
            "a".into(),
            "cost".into(),
            12,
            "ev".into(),
            1,
        )
        .await
        .unwrap();
        let diag = db
            .image_spend_diagnostic("epoch1".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(diag.state, "budget_violation");
        assert!(diag.debt_usd_micros > 0);

        // A reservation whose clock rolls into a NEW epoch is still blocked by
        // the global project debt (ProjectDebt), proving debt is not
        // epoch-filtered.
        let blocked = db
            .reserve_image_spend(
                "epoch2".into(),
                keys("plan-2"),
                vec![AttemptMaximum {
                    attempt_id: "b".into(),
                    usd_micros: Some(1),
                }],
                1,
                86_400_000,
            )
            .await;
        assert!(blocked.is_err());

        // After the debt is explicitly resolved, the new epoch reserves with a
        // clean per-epoch `used` accounting (full limit available again).
        db.resolve_image_spend_debt("epoch1".into(), "reviewed".into(), 2)
            .await
            .unwrap();
        let reserved = db
            .reserve_image_spend(
                "epoch2".into(),
                keys("plan-2"),
                vec![AttemptMaximum {
                    attempt_id: "b".into(),
                    usd_micros: Some(20),
                }],
                1,
                86_400_000,
            )
            .await
            .unwrap();
        assert_eq!(reserved.reserved_usd_micros, Some(20));
        assert_eq!(
            db.image_spend_diagnostic("epoch2".into())
                .await
                .unwrap()
                .unwrap()
                .epoch_sequence,
            2
        );
    }
}

impl<'de> Deserialize<'de> for BudgetPolicy {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Raw {
            Unconfigured,
            Finite { usd_micros: u64 },
            Unlimited,
        }
        match Raw::deserialize(d)? {
            Raw::Unconfigured => Ok(Self::Unconfigured),
            Raw::Finite { usd_micros: 0 } => Err(serde::de::Error::custom(
                "finite image spend budget must be positive",
            )),
            Raw::Finite { usd_micros } => Ok(Self::Finite { usd_micros }),
            Raw::Unlimited => Ok(Self::Unlimited),
        }
    }
}

/// Latest persisted policy row: (version, settings_json, epoch_policy_version,
/// rolling_anchor_unix_ms, rolling_anchor_sequence) — the last two are the
/// server-owned rolling anchor columns.
type LatestPolicyRow = Option<(u64, String, u64, Option<i64>, Option<i64>)>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedInstant {
    pub unix_ms: i64,
    pub monotonic_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectEpochPolicy {
    CalendarMonth {
        time_zone: String,
    },
    /// A user-constructible rolling window. Callers supply only the window
    /// length; the anchor (`SavedInstant`) is server-owned and stamped by
    /// `save_image_spend_policy`, so an "anchor-only change" is unrepresentable
    /// in this type and cannot be smuggled in through a config layer or RPC.
    Rolling {
        duration_seconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProjectEpoch {
    pub membership_key: String,
    pub interval_start_ms: i64,
}

impl ProjectEpochPolicy {
    pub fn validate(&self) -> std::result::Result<(), BudgetBlockReason> {
        match self {
            Self::CalendarMonth { time_zone }
                if time_zone.trim() != time_zone || jiff::tz::TimeZone::get(time_zone).is_err() =>
            {
                Err(BudgetBlockReason::InvalidProjectEpoch)
            }
            Self::Rolling {
                duration_seconds, ..
            } if !(86_400..=31_622_400).contains(duration_seconds) => {
                Err(BudgetBlockReason::InvalidProjectEpoch)
            }
            _ => Ok(()),
        }
    }

    /// Resolve membership from authoritative tzdb/rolling arithmetic. The
    /// returned start is persisted and the DB monotonic head prevents a wall
    /// clock rollback from reopening an older interval.
    ///
    /// `rolling_anchor` is the server-owned anchor persisted alongside the
    /// policy version (see `save_image_spend_policy`). It is required for a
    /// `Rolling` window and ignored for `CalendarMonth`; a missing anchor for a
    /// rolling policy is a fail-closed `InvalidProjectEpoch`.
    pub fn resolve_epoch(
        &self,
        now_unix_ms: i64,
        rolling_anchor: Option<&SavedInstant>,
    ) -> std::result::Result<ResolvedProjectEpoch, BudgetBlockReason> {
        self.validate()?;
        match self {
            Self::CalendarMonth { time_zone } => {
                let zone = jiff::tz::TimeZone::get(time_zone)
                    .map_err(|_| BudgetBlockReason::InvalidProjectEpoch)?;
                let now = jiff::Timestamp::from_millisecond(now_unix_ms)
                    .map_err(|_| BudgetBlockReason::InvalidProjectEpoch)?
                    .to_zoned(zone.clone());
                let start = jiff::civil::date(now.year(), now.month(), 1)
                    .at(0, 0, 0, 0)
                    .to_zoned(zone)
                    .map_err(|_| BudgetBlockReason::InvalidProjectEpoch)?;
                Ok(ResolvedProjectEpoch {
                    membership_key: format!("{:04}-{:02}@{time_zone}", now.year(), now.month()),
                    interval_start_ms: start.timestamp().as_millisecond(),
                })
            }
            Self::Rolling { duration_seconds } => {
                let anchor = rolling_anchor.ok_or(BudgetBlockReason::InvalidProjectEpoch)?;
                let duration_ms = i64::try_from(*duration_seconds)
                    .ok()
                    .and_then(|value| value.checked_mul(1_000))
                    .ok_or(BudgetBlockReason::InvalidProjectEpoch)?;
                let elapsed = now_unix_ms
                    .checked_sub(anchor.unix_ms)
                    .ok_or(BudgetBlockReason::InvalidProjectEpoch)?;
                if elapsed < 0 {
                    return Err(BudgetBlockReason::InvalidProjectEpoch);
                }
                let offset = elapsed / duration_ms;
                let start = anchor
                    .unix_ms
                    .checked_add(
                        offset
                            .checked_mul(duration_ms)
                            .ok_or(BudgetBlockReason::InvalidProjectEpoch)?,
                    )
                    .ok_or(BudgetBlockReason::InvalidProjectEpoch)?;
                let sequence = anchor
                    .monotonic_sequence
                    .checked_add(
                        u64::try_from(offset)
                            .map_err(|_| BudgetBlockReason::InvalidProjectEpoch)?,
                    )
                    .ok_or(BudgetBlockReason::InvalidProjectEpoch)?;
                Ok(ResolvedProjectEpoch {
                    membership_key: format!("rolling:{sequence}"),
                    interval_start_ms: start,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageSpendSettings {
    #[serde(default)]
    pub request: BudgetPolicy,
    #[serde(default)]
    pub session: BudgetPolicy,
    #[serde(default)]
    pub project: BudgetPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_epoch: Option<ProjectEpochPolicy>,
}

impl ImageSpendSettings {
    pub fn validate(&self) -> std::result::Result<(), BudgetBlockReason> {
        if self.request == BudgetPolicy::Unconfigured {
            return Err(BudgetBlockReason::RequestUnconfigured);
        }
        if self.session == BudgetPolicy::Unconfigured {
            return Err(BudgetBlockReason::SessionUnconfigured);
        }
        if self.project == BudgetPolicy::Unconfigured {
            return Err(BudgetBlockReason::ProjectUnconfigured);
        }
        if let Some(epoch) = &self.project_epoch {
            epoch.validate()?;
        }
        if matches!(self.project, BudgetPolicy::Finite { .. }) {
            self.project_epoch
                .as_ref()
                .ok_or(BudgetBlockReason::ProjectEpochUnconfigured)?
                .validate()?;
        }
        Ok(())
    }
    pub fn all_unlimited(&self) -> bool {
        self.request == BudgetPolicy::Unlimited
            && self.session == BudgetPolicy::Unlimited
            && self.project == BudgetPolicy::Unlimited
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetBlockReason {
    RequestUnconfigured,
    SessionUnconfigured,
    ProjectUnconfigured,
    ProjectEpochUnconfigured,
    InvalidProjectEpoch,
    UnknownMaximumWithFinitePolicy,
    ArithmeticOverflow,
    RequestExhausted,
    SessionExhausted,
    ProjectExhausted,
    RequestDebt,
    SessionDebt,
    ProjectDebt,
    PolicyVersionChanged,
    ReservationTerminal,
    EmptyPlan,
}

impl std::fmt::Display for BudgetBlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BudgetBlockReason {}

/// Error raised when an identity newtype is constructed from a value that is
/// not in non-empty canonical form (empty, or surrounded by whitespace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendScopeKeyError {
    EmptyProjectKey,
    EmptySessionId,
}

impl std::fmt::Display for SpendScopeKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SpendScopeKeyError {}

/// Canonicalize an identity string: it must be non-empty and free of leading or
/// trailing whitespace. Returns the canonical owned string on success.
fn canonical_identity(value: impl Into<String>) -> Option<String> {
    let value = value.into();
    if value.is_empty() || value.trim() != value {
        return None;
    }
    Some(value)
}

/// A validated, non-empty project identity. Constructible only through
/// [`ProjectKey::new`] (from a project-identity API or a test fixture), so an
/// empty or whitespace-padded project key is unrepresentable at every spend
/// call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectKey(String);

impl ProjectKey {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, SpendScopeKeyError> {
        canonical_identity(value)
            .map(Self)
            .ok_or(SpendScopeKeyError::EmptyProjectKey)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated, non-empty session identity. Constructible only through
/// [`SessionId::new`] (from the session store or a test fixture), so an empty or
/// whitespace-padded session id is unrepresentable at every spend call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(value: impl Into<String>) -> std::result::Result<Self, SpendScopeKeyError> {
        canonical_identity(value)
            .map(Self)
            .ok_or(SpendScopeKeyError::EmptySessionId)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendScopeKeys {
    /// Unique immutable request-plan identity, including the request nonce.
    /// Replays retain this digest; a distinct rerun must mint a new digest.
    pub plan_digest: String,
    /// Validated session identity; empty/whitespace values are constructor-rejected.
    pub session_id: SessionId,
    /// Validated project identity; empty/whitespace values are constructor-rejected.
    pub project_key: ProjectKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptMaximum {
    pub attempt_id: String,
    pub usd_micros: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendReservation {
    pub reservation_id: String,
    pub reserved_usd_micros: Option<u64>,
    pub cost_unknown: bool,
    pub policy_version: u64,
}

pub struct ReserveAndPrepareImageSpend {
    pub reservation_id: String,
    pub keys: SpendScopeKeys,
    pub attempts: Vec<AttemptMaximum>,
    pub expected_policy_version: u64,
    pub attempt_id: String,
    pub journal: PrepareExternalOperation,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendLedgerDiagnostic {
    pub reservation_id: String,
    pub policy_version: u64,
    pub epoch_policy_version: u64,
    pub epoch_sequence: u64,
    pub state: String,
    pub reserved_usd_micros: Option<u64>,
    pub charged_usd_micros: u64,
    pub debt_usd_micros: u64,
}

struct SpendLedgerDiagnosticRow {
    policy_version: i64,
    epoch_policy_version: i64,
    epoch_sequence: i64,
    state: String,
    reserved_usd_micros: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentImageSpendPolicy {
    pub settings: ImageSpendSettings,
    pub policy_version: u64,
    pub epoch_policy_version: u64,
    pub epoch_sequence: Option<u64>,
    /// Read-model view of the server-owned rolling anchor for display. Present
    /// only when `settings.project_epoch` is `Rolling`; the anchor never
    /// round-trips through the user-constructible settings type.
    pub effective_rolling_anchor: Option<SavedInstant>,
}

impl Db {
    pub async fn current_image_spend_policy(
        &self,
        project_key: String,
    ) -> Result<Option<CurrentImageSpendPolicy>> {
        self.read(move |conn| conn.query_row("SELECT p.settings_json,p.version,p.epoch_policy_version,(SELECT epoch_sequence FROM image_spend_epoch_heads h WHERE h.project_key=p.project_key AND h.epoch_policy_version=p.epoch_policy_version),p.rolling_anchor_unix_ms,p.rolling_anchor_sequence FROM image_spend_policy_versions p WHERE p.project_key=?1 ORDER BY p.version DESC LIMIT 1",[project_key],|row|Ok(CurrentImageSpendPolicy{settings:serde_json::from_str::<ImageSpendSettings>(&row.get::<_,String>(0)?).map_err(|e|rusqlite::Error::FromSqlConversionFailure(0,rusqlite::types::Type::Text,Box::new(e)))?,policy_version:read_u64(row.get(1)?)?,epoch_policy_version:read_u64(row.get(2)?)?,epoch_sequence:row.get::<_,Option<i64>>(3)?.map(read_u64).transpose()?,effective_rolling_anchor:match (row.get::<_,Option<i64>>(4)?,row.get::<_,Option<i64>>(5)?){(Some(unix_ms),Some(sequence))=>Some(SavedInstant{unix_ms,monotonic_sequence:read_u64(sequence)?}),_=>None}})).optional().map_err(Into::into)).await
    }
    pub async fn image_spend_diagnostic(
        &self,
        reservation_id: String,
    ) -> Result<Option<SpendLedgerDiagnostic>> {
        self.read(move |conn| {
            let base: Option<SpendLedgerDiagnosticRow> = conn.query_row(
                "SELECT policy_version,epoch_policy_version,epoch_sequence,state,reserved_usd_micros FROM image_spend_reservations WHERE reservation_id=?1",
                [&reservation_id], |row| Ok(SpendLedgerDiagnosticRow {
                    policy_version: row.get(0)?,
                    epoch_policy_version: row.get(1)?,
                    epoch_sequence: row.get(2)?,
                    state: row.get(3)?,
                    reserved_usd_micros: row.get(4)?,
                }),
            ).optional()?;
            let Some(base)=base else{return Ok(None)};
            let debt = { let mut statement=conn.prepare("SELECT debt_usd_micros FROM image_spend_scope_usage WHERE reservation_id=?1")?; let values=statement.query_map([&reservation_id],|row|row.get::<_,Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?; values.into_iter().map(read_money).collect::<rusqlite::Result<Vec<_>>>()?.into_iter().max().unwrap_or(0) };
            let charged = sum_reservation_money(conn, &reservation_id, "SELECT actual_usd_micros FROM image_spend_cost_events WHERE reservation_id=?1")?;
            Ok(Some(SpendLedgerDiagnostic { reservation_id, policy_version:read_u64(base.policy_version)?, epoch_policy_version:read_u64(base.epoch_policy_version)?, epoch_sequence:read_u64(base.epoch_sequence)?, state:base.state, reserved_usd_micros:base.reserved_usd_micros.map(read_money).transpose()?, charged_usd_micros:charged, debt_usd_micros:debt }))
        }).await
    }
    /// Resolve a caller-derived calendar/rolling membership to a durable,
    /// monotonic sequence. A changed wall-clock label can only advance; it can
    /// never select an older sequence after clock rollback.
    #[cfg(test)]
    pub async fn resolve_image_spend_epoch(
        &self,
        project_key: String,
        epoch_policy_version: u64,
        membership_key: String,
        interval_start_ms: i64,
        resolved_at_ms: i64,
    ) -> Result<u64> {
        let epoch_policy_version_sql = sqlite_u64(epoch_policy_version)?;
        self.transaction(move |conn| {
            let current: Option<(i64,String,i64)> = conn.query_row("SELECT epoch_sequence,membership_key,interval_start_ms FROM image_spend_epoch_heads WHERE project_key=?1 AND epoch_policy_version=?2",params![project_key,epoch_policy_version_sql],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            if let Some((sequence,current_key,current_start))=current {
                if current_key == membership_key { return u64::try_from(sequence).context("negative epoch sequence"); }
                if interval_start_ms <= current_start { bail!("clock rollback cannot reopen an image spend epoch"); }
                let next=sequence.checked_add(1).ok_or(BudgetBlockReason::ArithmeticOverflow)?;
                conn.execute("UPDATE image_spend_epoch_heads SET epoch_sequence=?3,membership_key=?4,interval_start_ms=?5,resolved_at_ms=?6 WHERE project_key=?1 AND epoch_policy_version=?2 AND epoch_sequence=?7",params![project_key,epoch_policy_version_sql,next,membership_key,interval_start_ms,resolved_at_ms,sequence])?;
                return u64::try_from(next).context("negative epoch sequence");
            }
            conn.execute("INSERT INTO image_spend_epoch_heads(project_key,epoch_policy_version,epoch_sequence,membership_key,interval_start_ms,resolved_at_ms) VALUES(?1,?2,1,?3,?4,?5)",params![project_key,epoch_policy_version_sql,membership_key,interval_start_ms,resolved_at_ms])?;
            Ok(1)
        }).await
    }
    /// Save a reviewed policy. Every save creates a new immutable version;
    /// ledger rows retain their original version and resolved epoch.
    pub async fn save_image_spend_policy(
        &self,
        project_key: String,
        settings: ImageSpendSettings,
        expected_current_version: Option<u64>,
        saved_at_ms: i64,
    ) -> Result<u64> {
        settings.validate().map_err(anyhow::Error::new)?;
        self.transaction(move |conn| {
            save_image_spend_policy_conn(
                conn,
                &project_key,
                &settings,
                expected_current_version,
                saved_at_ms,
            )
        })
        .await
    }

    /// Persist an image spend policy on an existing writer transaction.
    ///
    /// Daemon control-plane callers use this seam to commit the immutable
    /// policy version and its exactly-once operation receipt atomically.
    pub fn save_image_spend_policy_conn(
        conn: &rusqlite::Connection,
        project_key: &str,
        settings: &ImageSpendSettings,
        expected_current_version: Option<u64>,
        saved_at_ms: i64,
    ) -> Result<u64> {
        settings.validate().map_err(anyhow::Error::new)?;
        let current: LatestPolicyRow = conn.query_row("SELECT version,settings_json,epoch_policy_version,rolling_anchor_unix_ms,rolling_anchor_sequence FROM image_spend_policy_versions WHERE project_key=?1 ORDER BY version DESC LIMIT 1", [&project_key], |r| Ok((read_u64(r.get(0)?)?,r.get(1)?,read_u64(r.get(2)?)?,r.get(3)?,r.get(4)?))).optional()?;
        if current.as_ref().map(|v| v.0) != expected_current_version {
            return Err(BudgetBlockReason::PolicyVersionChanged.into());
        }
        let version = current.as_ref().map_or(Ok(1), |v| {
            v.0.checked_add(1)
                .ok_or(BudgetBlockReason::ArithmeticOverflow)
        })?;
        let previous_epoch = current
            .as_ref()
            .and_then(|v| serde_json::from_str::<ImageSpendSettings>(&v.1).ok())
            .and_then(|s| s.project_epoch);
        // The rolling anchor is server-owned; it is persisted in adjacent
        // columns, never inside the user-constructible settings JSON.
        let previous_rolling_anchor: Option<(i64, u64)> = match (
            current.as_ref().and_then(|v| v.3),
            current.as_ref().and_then(|v| v.4),
        ) {
            (Some(unix_ms), Some(sequence)) => Some((unix_ms, read_u64(sequence)?)),
            _ => None,
        };
        let same_epoch_policy = match (&previous_epoch, &settings.project_epoch) {
            (
                Some(ProjectEpochPolicy::CalendarMonth { time_zone: left }),
                Some(ProjectEpochPolicy::CalendarMonth { time_zone: right }),
            ) => left == right,
            (
                Some(ProjectEpochPolicy::Rolling {
                    duration_seconds: left,
                }),
                Some(ProjectEpochPolicy::Rolling {
                    duration_seconds: right,
                }),
            ) => left == right,
            (None, None) => true,
            _ => false,
        };
        let epoch_policy_version = current.as_ref().map_or(Ok(1), |v| {
            if same_epoch_policy {
                Ok(v.2)
            } else {
                v.2.checked_add(1)
                    .ok_or(BudgetBlockReason::ArithmeticOverflow)
            }
        })?;
        // Server-stamp (or reuse) the rolling anchor. A same-duration
        // Rolling->Rolling save keeps the previous anchor, so an anchor is
        // never a user-visible, independently changeable input.
        let rolling_anchor: Option<(i64, u64)> = match &settings.project_epoch {
            Some(ProjectEpochPolicy::Rolling { duration_seconds }) => {
                match (&previous_epoch, previous_rolling_anchor) {
                    (
                        Some(ProjectEpochPolicy::Rolling {
                            duration_seconds: previous_duration,
                        }),
                        Some(previous_anchor),
                    ) if previous_duration == duration_seconds => Some(previous_anchor),
                    _ => Some((saved_at_ms, epoch_policy_version)),
                }
            }
            _ => None,
        };
        let (anchor_unix_ms, anchor_sequence): (Option<i64>, Option<i64>) = match rolling_anchor {
            Some((unix_ms, sequence)) => (Some(unix_ms), Some(sqlite_u64(sequence)?)),
            None => (None, None),
        };
        let json = serde_json::to_string(&settings)?;
        conn.execute("INSERT INTO image_spend_policy_versions(project_key,version,epoch_policy_version,settings_json,saved_at_ms,rolling_anchor_unix_ms,rolling_anchor_sequence) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![project_key, sqlite_u64(version)?, sqlite_u64(epoch_policy_version)?, json, saved_at_ms, anchor_unix_ms, anchor_sequence])?;
        Ok(version)
    }

    /// Atomically reserve the checked conservative sum at request, session,
    /// and resolved project-epoch scope before any provider contact.
    pub async fn reserve_image_spend(
        &self,
        reservation_id: String,
        keys: SpendScopeKeys,
        attempts: Vec<AttemptMaximum>,
        expected_policy_version: u64,
        created_at_ms: i64,
    ) -> Result<SpendReservation> {
        self.reserve_image_spend_impl(
            reservation_id,
            keys,
            attempts,
            expected_policy_version,
            created_at_ms,
            None,
        )
        .await
        .map(|(reservation, _)| reservation)
    }

    pub async fn reserve_and_prepare_image_spend(
        &self,
        request: ReserveAndPrepareImageSpend,
    ) -> Result<(SpendReservation, ExternalJournalRecord)> {
        let ReserveAndPrepareImageSpend {
            reservation_id,
            keys,
            attempts,
            expected_policy_version,
            attempt_id,
            journal,
            created_at_ms,
        } = request;
        let (reservation, prepared) = self
            .reserve_image_spend_impl(
                reservation_id,
                keys,
                attempts,
                expected_policy_version,
                created_at_ms,
                Some((attempt_id, journal)),
            )
            .await?;
        Ok((
            reservation,
            prepared.context("atomic journal preparation was absent")?,
        ))
    }

    async fn reserve_image_spend_impl(
        &self,
        reservation_id: String,
        keys: SpendScopeKeys,
        attempts: Vec<AttemptMaximum>,
        expected_policy_version: u64,
        created_at_ms: i64,
        journal: Option<(String, PrepareExternalOperation)>,
    ) -> Result<(SpendReservation, Option<ExternalJournalRecord>)> {
        self.transaction(move |conn| {
            if let Some((existing,state,plan,session,project)) = conn.query_row("SELECT reserved_usd_micros,cost_unknown,policy_version,state,plan_digest,session_id,project_key FROM image_spend_reservations WHERE reservation_id=?1", [&reservation_id], |r| Ok((SpendReservation { reservation_id: reservation_id.clone(), reserved_usd_micros: r.get::<_,Option<Vec<u8>>>(0)?.map(read_money).transpose()?, cost_unknown: r.get::<_,i64>(1)? != 0, policy_version: read_u64(r.get(2)?)? },r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?))).optional()? {
                if state != "reserved" { return Err(BudgetBlockReason::ReservationTerminal.into()); }
                if plan != keys.plan_digest || session != keys.session_id.as_str() || project != keys.project_key.as_str() || existing.policy_version != expected_policy_version { bail!("reservation replay does not match active immutable plan"); }
                let stored: Vec<(String,Option<Vec<u8>>)> = { let mut statement=conn.prepare("SELECT attempt_id,maximum_usd_micros FROM image_spend_attempts WHERE reservation_id=?1 ORDER BY attempt_id")?; statement.query_map([&reservation_id],|r|Ok((r.get(0)?,r.get(1)?)))?.collect::<rusqlite::Result<_>>()? };
                let mut requested: Vec<_> = attempts.iter().map(|a|(a.attempt_id.clone(),a.usd_micros)).collect(); requested.sort();
                let stored: Vec<_> = stored.into_iter().map(|(id,v)| Ok((id,v.map(read_money).transpose()?))).collect::<rusqlite::Result<_>>()?;
                if stored != requested { bail!("reservation replay attempts do not match immutable plan"); }
                if let Some((attempt_id,journal)) = journal {
                    let prepared=prepare_external_operation_conn(conn,&journal,created_at_ms)?;
                    let record=prepared.record().clone();
                    let bound: Option<String> = conn.query_row("SELECT external_operation_id FROM image_spend_attempt_dispatches WHERE reservation_id=?1 AND attempt_id=?2",params![reservation_id,attempt_id],|row|row.get(0)).optional()?;
                    let operation_id = record.operation_id.to_string();
                    if bound.as_deref() != Some(operation_id.as_str()) { bail!("reservation replay journal binding does not match"); }
                    return Ok((existing, Some(record)));
                }
                return Ok((existing, None));
            }
            let current: LatestPolicyRow = conn.query_row("SELECT version,settings_json,epoch_policy_version,rolling_anchor_unix_ms,rolling_anchor_sequence FROM image_spend_policy_versions WHERE project_key=?1 ORDER BY version DESC LIMIT 1", [keys.project_key.as_str()], |r| Ok((read_u64(r.get(0)?)?,r.get(1)?,read_u64(r.get(2)?)?,r.get(3)?,r.get(4)?))).optional()?;
            let (current_version,json,epoch_policy_version,anchor_unix_ms,anchor_sequence)=current.ok_or(BudgetBlockReason::ProjectUnconfigured)?;
            // The rolling anchor is server-owned and lives in adjacent policy
            // columns, never in the user-constructible settings JSON.
            let rolling_anchor: Option<SavedInstant> = match (anchor_unix_ms, anchor_sequence) {
                (Some(unix_ms), Some(sequence)) => Some(SavedInstant { unix_ms, monotonic_sequence: read_u64(sequence)? }),
                _ => None,
            };
            if current_version != expected_policy_version { return Err(BudgetBlockReason::PolicyVersionChanged.into()); }
            let settings: ImageSpendSettings = serde_json::from_str(&json)?;
            settings.validate().map_err(|r| anyhow::anyhow!("{r:?}"))?;
            if attempts.is_empty() {
                return Err(BudgetBlockReason::EmptyPlan.into());
            }
            let unknown = attempts.iter().any(|a| a.usd_micros.is_none());
            if unknown && !settings.all_unlimited() {
                return Err(BudgetBlockReason::UnknownMaximumWithFinitePolicy.into());
            }
            let total = attempts.iter().try_fold(0u64, |sum,a| a.usd_micros.map_or(Ok(sum), |v| sum.checked_add(v).ok_or(BudgetBlockReason::ArithmeticOverflow)))?;
            let total_sql = money_blob(total);
            let expected_policy_version_sql = sqlite_u64(expected_policy_version)?;
            let epoch_policy_version_sql = sqlite_u64(epoch_policy_version)?;
            let epoch_sequence = if matches!(settings.project, BudgetPolicy::Finite { .. }) {
                let resolved = settings.project_epoch.as_ref().ok_or(BudgetBlockReason::ProjectEpochUnconfigured)?.resolve_epoch(created_at_ms, rolling_anchor.as_ref())?;
                let head: Option<(i64,String,i64)> = conn.query_row("SELECT epoch_sequence,membership_key,interval_start_ms FROM image_spend_epoch_heads WHERE project_key=?1 AND epoch_policy_version=?2",params![keys.project_key.as_str(),epoch_policy_version_sql],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
                match head {
                    Some((sequence,key,_)) if key == resolved.membership_key => read_u64(sequence)?,
                    Some((sequence,_,start)) if resolved.interval_start_ms > start => {
                        let next=sequence.checked_add(1).ok_or(BudgetBlockReason::ArithmeticOverflow)?;
                        let changed=conn.execute("UPDATE image_spend_epoch_heads SET epoch_sequence=?3,membership_key=?4,interval_start_ms=?5,resolved_at_ms=?6 WHERE project_key=?1 AND epoch_policy_version=?2 AND epoch_sequence=?7",params![keys.project_key.as_str(),epoch_policy_version_sql,next,resolved.membership_key,resolved.interval_start_ms,created_at_ms,sequence])?;
                        if changed != 1 { return Err(BudgetBlockReason::PolicyVersionChanged.into()); }
                        read_u64(next)?
                    }
                    Some(_) => return Err(BudgetBlockReason::InvalidProjectEpoch.into()),
                    None => {
                        conn.execute("INSERT INTO image_spend_epoch_heads(project_key,epoch_policy_version,epoch_sequence,membership_key,interval_start_ms,resolved_at_ms) VALUES(?1,?2,1,?3,?4,?5)",params![keys.project_key.as_str(),epoch_policy_version_sql,resolved.membership_key,resolved.interval_start_ms,created_at_ms])?;
                        1
                    }
                }
            } else { 0 };
            let epoch_sequence_sql = sqlite_u64(epoch_sequence)?;
            conn.execute("INSERT INTO image_spend_reservations(reservation_id,plan_digest,session_id,project_key,policy_version,epoch_policy_version,epoch_sequence,reserved_usd_micros,cost_unknown,state,created_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'reserved',?10)", params![reservation_id,keys.plan_digest,keys.session_id.as_str(),keys.project_key.as_str(),expected_policy_version_sql,epoch_policy_version_sql,epoch_sequence_sql,if unknown { None } else { Some(total_sql.clone()) },unknown,created_at_ms])?;
            for (kind, scope_key, policy) in [("request", keys.plan_digest.as_str(), settings.request), ("session", keys.session_id.as_str(), settings.session), ("project", keys.project_key.as_str(), settings.project)] {
                if let BudgetPolicy::Finite { usd_micros: limit } = policy {
                    let epoch = if kind == "project" { epoch_sequence } else { 0 };
                    let epoch_policy = if kind == "project" { epoch_policy_version } else { 0 };
                    // INTENTIONAL debt-vs-used asymmetry (do NOT epoch-filter debt
                    // without an explicit product decision — see the test
                    // `project_debt_is_global_used_is_epoch_scoped`):
                    //  - `used` is epoch-scoped for the `project` kind (a new
                    //    project epoch starts its spend accounting clean), gated
                    //    by the `epoch_policy_version`/`epoch_sequence` predicate.
                    //  - `debt` sums across ALL epochs for the scope key with NO
                    //    epoch predicate. Unresolved overage on a project scope key
                    //    is deliberately conservative: it keeps blocking new epochs
                    //    until the debt is explicitly resolved, so a rollover cannot
                    //    silently wipe an outstanding budget violation.
                    let used = { let mut statement=conn.prepare("SELECT reserved_usd_micros FROM image_spend_scope_usage WHERE scope_kind=?1 AND scope_key=?2 AND (?3!='project' OR (epoch_policy_version=?4 AND epoch_sequence=?5))")?; let values=statement.query_map(params![kind,scope_key,kind,sqlite_u64(epoch_policy)?,sqlite_u64(epoch)?],|r|r.get::<_,Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?; values.into_iter().try_fold(0u64,|sum,value|sum.checked_add(read_money(value)?).ok_or_else(||anyhow::Error::new(BudgetBlockReason::ArithmeticOverflow)))? };
                    let debt = { let mut statement=conn.prepare("SELECT debt_usd_micros FROM image_spend_scope_usage WHERE scope_kind=?1 AND scope_key=?2")?; let values=statement.query_map(params![kind,scope_key],|r|r.get::<_,Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?; values.into_iter().try_fold(0u64,|sum,value|sum.checked_add(read_money(value)?).ok_or_else(||anyhow::Error::new(BudgetBlockReason::ArithmeticOverflow)))? };
                    let reason = match kind { "request" => if debt > 0 { BudgetBlockReason::RequestDebt } else { BudgetBlockReason::RequestExhausted }, "session" => if debt > 0 { BudgetBlockReason::SessionDebt } else { BudgetBlockReason::SessionExhausted }, _ => if debt > 0 { BudgetBlockReason::ProjectDebt } else { BudgetBlockReason::ProjectExhausted } };
                    let projected=used.checked_add(total).ok_or(BudgetBlockReason::ArithmeticOverflow)?;
                    if debt > 0 || projected > limit { return Err(reason.into()); }
                    conn.execute("INSERT INTO image_spend_scope_usage(reservation_id,scope_kind,scope_key,policy_version,epoch_policy_version,epoch_sequence,reserved_usd_micros,charged_usd_micros,debt_usd_micros) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8)", params![reservation_id,kind,scope_key,expected_policy_version_sql,sqlite_u64(epoch_policy)?,sqlite_u64(epoch)?,total_sql,money_blob(0)])?;
                }
            }
            for attempt in attempts { conn.execute("INSERT INTO image_spend_attempts(reservation_id,attempt_id,maximum_usd_micros) VALUES(?1,?2,?3)",params![reservation_id,attempt.attempt_id,attempt.usd_micros.map(money_blob)])?; }
            let reservation = SpendReservation { reservation_id: reservation_id.clone(), reserved_usd_micros: (!unknown).then_some(total), cost_unknown: unknown, policy_version: expected_policy_version };
            let prepared = if let Some((attempt_id,journal)) = journal {
                if journal.operation_kind.as_str() != "image_generation" || journal.owner_session_id.as_str() != keys.session_id.as_str() { bail!("atomic image dispatch journal identity is invalid"); }
                let prepared=prepare_external_operation_conn(conn,&journal,created_at_ms)?;
                if matches!(&prepared, ExternalPrepareOutcome::Existing(_)) { bail!("external operation already exists outside this reservation"); }
                let record=prepared.record().clone();
                conn.execute("INSERT INTO image_spend_attempt_dispatches(reservation_id,attempt_id,external_operation_id) VALUES(?1,?2,?3)",params![reservation_id,attempt_id,record.operation_id.to_string()])?;
                Some(record)
            } else { None };
            Ok((reservation, prepared))
        }).await
    }

    /// Atomically bind one already-reserved attempt to a durable external
    /// journal identity. A provider adapter must obtain this record before it
    /// can begin handoff; raw prompt/provider payload bytes are never stored.
    pub async fn prepare_image_spend_dispatch(
        &self,
        reservation_id: String,
        attempt_id: String,
        journal: PrepareExternalOperation,
        at_ms: i64,
    ) -> Result<ExternalJournalRecord> {
        if journal.operation_kind.as_str() != "image_generation" {
            bail!("image spend dispatch requires image_generation journal kind");
        }
        self.transaction(move |conn| {
            prepare_reserved_image_spend_dispatch_conn(
                conn,
                &reservation_id,
                &attempt_id,
                &journal,
                at_ms,
            )
        })
        .await
    }

    /// Commit the durable `dispatching` proof immediately before provider
    /// contact. A conflict returns the authoritative current journal record.
    pub async fn begin_image_spend_dispatch(
        &self,
        reservation_id: String,
        attempt_id: String,
        operation_id: Uuid,
        expected_version: i64,
        at_ms: i64,
    ) -> Result<ExternalTransitionOutcome> {
        self.transaction(move |conn| {
            let bound: Option<i64> = conn.query_row(
                "SELECT 1 FROM image_spend_attempt_dispatches d JOIN image_spend_reservations r USING(reservation_id) WHERE d.reservation_id=?1 AND d.attempt_id=?2 AND d.external_operation_id=?3 AND r.state='reserved'",
                params![reservation_id, attempt_id, operation_id.to_string()], |row| row.get(0),
            ).optional()?;
            if bound.is_none() { bail!("external operation is not bound to the image spend attempt"); }
            transition_external_operation_conn(conn, operation_id, expected_version, ExternalJournalState::Dispatching, at_ms)
        }).await
    }

    /// Record authoritative provider handoff evidence. Only a journal-backed
    /// definitive rejection can release a hold; accepted and ambiguous
    /// submissions retain it for billing reconciliation.
    pub async fn finish_image_spend_dispatch(
        &self,
        reservation_id: String,
        attempt_id: String,
        operation_id: Uuid,
        expected_version: i64,
        evidence: ImageSpendDispatchEvidence,
        at_ms: i64,
    ) -> Result<ExternalTransitionOutcome> {
        self.transaction(move |conn| {
            finish_reserved_image_spend_dispatch_conn(
                conn,
                &reservation_id,
                &attempt_id,
                operation_id,
                expected_version,
                evidence,
                at_ms,
            )
        })
        .await
    }

    /// Apply one authoritative billing identity exactly once. Actual cost is
    /// never capped; overage becomes debt on every affected finite scope.
    pub async fn reconcile_image_spend(
        &self,
        reservation_id: String,
        attempt_id: String,
        cost_identity: String,
        actual_usd_micros: u64,
        evidence_ref: String,
        at_ms: i64,
    ) -> Result<bool> {
        let actual_usd_micros_sql = money_blob(actual_usd_micros);
        self.transaction(move |conn| {
            if conn.query_row("SELECT 1 FROM image_spend_cost_events WHERE cost_identity=?1",[&cost_identity],|r|r.get::<_,i64>(0)).optional()?.is_some() { return Ok(false); }
            conn.execute("INSERT INTO image_spend_cost_events(cost_identity,reservation_id,attempt_id,actual_usd_micros,evidence_ref,recorded_at_ms) VALUES(?1,?2,?3,?4,?5,?6)",params![cost_identity,reservation_id,attempt_id,actual_usd_micros_sql,evidence_ref,at_ms])?;
            let (reserved, unknown, prior_state): (Option<Vec<u8>>,i64,String) = conn.query_row("SELECT reserved_usd_micros,cost_unknown,state FROM image_spend_reservations WHERE reservation_id=?1",[&reservation_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            let charged = sum_reservation_money(conn, &reservation_id, "SELECT actual_usd_micros FROM image_spend_cost_events WHERE reservation_id=?1")?;
            let resolved = sum_reservation_money(conn, &reservation_id, "SELECT resolved_debt_usd_micros FROM image_spend_debt_resolutions WHERE reservation_id=?1")?;
            let debt = if unknown != 0 { 0 } else { charged.saturating_sub(reserved.map(read_money).transpose()?.unwrap_or(0)).saturating_sub(resolved) };
            let remaining = if prior_state == "released" { 0 } else { sum_reservation_money(conn, &reservation_id, "SELECT maximum_usd_micros FROM image_spend_attempts a WHERE reservation_id=?1 AND maximum_usd_micros IS NOT NULL AND NOT EXISTS(SELECT 1 FROM image_spend_cost_events e WHERE e.reservation_id=a.reservation_id AND e.attempt_id=a.attempt_id)")? };
            let held = charged.checked_add(remaining).ok_or(BudgetBlockReason::ArithmeticOverflow)?;
            conn.execute("UPDATE image_spend_scope_usage SET charged_usd_micros=?2,reserved_usd_micros=?3,debt_usd_micros=?4 WHERE reservation_id=?1",params![reservation_id,money_blob(charged),money_blob(held),money_blob(debt)])?;
            conn.execute("UPDATE image_spend_reservations SET state=CASE WHEN ?3<>X'0000000000000000' THEN 'budget_violation' WHEN ?2=1 THEN 'reconciled' WHEN ?4='released' AND EXISTS(SELECT 1 FROM image_spend_cost_events e WHERE e.reservation_id=?1) THEN 'reconciled' WHEN EXISTS(SELECT 1 FROM image_spend_cost_events e WHERE e.reservation_id=?1) AND NOT EXISTS(SELECT 1 FROM image_spend_attempts a WHERE a.reservation_id=?1 AND NOT EXISTS(SELECT 1 FROM image_spend_cost_events e WHERE e.reservation_id=a.reservation_id AND e.attempt_id=a.attempt_id)) THEN 'reconciled' WHEN ?4='released' THEN 'released' WHEN EXISTS(SELECT 1 FROM image_spend_attempts a WHERE a.reservation_id=?1 AND NOT EXISTS(SELECT 1 FROM image_spend_cost_events e WHERE e.reservation_id=a.reservation_id AND e.attempt_id=a.attempt_id)) THEN 'reserved' ELSE 'reconciled' END WHERE reservation_id=?1",params![reservation_id,unknown,money_blob(debt),prior_state])?;
            Ok(true)
        }).await
    }

    /// Release a reservation only while durable journal evidence proves that
    /// none of its attempts reached provider handoff.
    pub async fn cancel_image_spend_before_dispatch(
        &self,
        reservation_id: String,
        at_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let possibly_accepted: i64 = conn.query_row(
                "SELECT COUNT(*) FROM image_spend_attempt_dispatches d JOIN external_journal_operations o ON o.operation_id=d.external_operation_id WHERE d.reservation_id=?1 AND o.state IN ('dispatching','accepted','submission_unknown')",
                [&reservation_id], |row| row.get(0),
            )?;
            if possibly_accepted != 0 {
                bail!("provider acceptance is possible; retain the image spend reservation");
            }
            let rejected_or_unprepared: i64 = conn.query_row(
                "SELECT COUNT(*) FROM image_spend_attempts a LEFT JOIN image_spend_attempt_dispatches d USING(reservation_id,attempt_id) LEFT JOIN external_journal_operations o ON o.operation_id=d.external_operation_id WHERE a.reservation_id=?1 AND (d.external_operation_id IS NULL OR o.state IN ('prepared','rejected'))",
                [&reservation_id], |row| row.get(0),
            )?;
            let attempts: i64 = conn.query_row("SELECT COUNT(*) FROM image_spend_attempts WHERE reservation_id=?1",[&reservation_id],|row|row.get(0))?;
            if attempts == 0 || rejected_or_unprepared != attempts { bail!("authoritative pre-provider evidence is incomplete"); }
            let changed=conn.execute("UPDATE image_spend_reservations SET state='released',release_proof_identity='journal:no-provider-dispatch',released_at_ms=?2 WHERE reservation_id=?1 AND state='reserved'",params![reservation_id,at_ms])?;
            if changed != 0 { conn.execute("UPDATE image_spend_scope_usage SET reserved_usd_micros=charged_usd_micros WHERE reservation_id=?1",[reservation_id])?; }
            Ok(changed != 0)
        }).await
    }

    /// Explicitly acknowledge and clear recorded debt after external billing
    /// reconciliation. This never changes the authoritative charge.
    pub async fn resolve_image_spend_debt(
        &self,
        reservation_id: String,
        resolution_ref: String,
        at_ms: i64,
    ) -> Result<bool> {
        self.transaction(move |conn| {
            let amount = { let mut statement=conn.prepare("SELECT debt_usd_micros FROM image_spend_scope_usage WHERE reservation_id=?1")?; let values=statement.query_map([&reservation_id],|row|row.get::<_,Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?; values.into_iter().map(read_money).collect::<rusqlite::Result<Vec<_>>>()?.into_iter().max().unwrap_or(0) };
            let changed=conn.execute("UPDATE image_spend_scope_usage SET debt_usd_micros=?2 WHERE reservation_id=?1 AND debt_usd_micros<>?2",params![reservation_id,money_blob(0)])?;
            if changed > 0 { conn.execute("INSERT INTO image_spend_debt_resolutions(reservation_id,resolution_ref,resolved_debt_usd_micros,resolved_at_ms) VALUES(?1,?2,?3,?4)",params![reservation_id,resolution_ref,money_blob(amount),at_ms])?; }
            Ok(changed > 0)
        }).await
    }
}
