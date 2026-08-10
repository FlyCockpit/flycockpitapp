//! Provider-neutral paid image dispatch boundary.
//!
//! Concrete image adapters plug into [`PaidImageProvider`]. They never receive
//! control until the immutable plan has reserved every finite scope and the
//! external journal is durably in `dispatching`.

use std::future::Future;
use std::pin::Pin;

use cockpit_db::Db;
use cockpit_db::db::external_journal::{
    ExternalJournalDigest, ExternalJournalToken, PrepareExternalOperation,
};
use cockpit_db::db::image_spend::{
    AttemptMaximum, ImageSpendDispatchEvidence, ReserveAndPrepareImageSpend, SpendReservation,
    SpendScopeKeys,
};

pub struct PaidImagePlan {
    pub reservation_id: String,
    pub scopes: SpendScopeKeys,
    pub attempts: Vec<AttemptMaximum>,
    pub policy_version: u64,
    pub created_at_ms: i64,
}

pub trait PaidImageProvider: Send + Sync {
    fn handoff<'a>(
        &'a self,
        attempt_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<ImageSpendDispatchEvidence>> + Send + 'a>>;
}

pub struct PaidImageDispatch {
    pub plan: PaidImagePlan,
    pub attempt_id: String,
    pub session_id: String,
    pub idempotency_key: String,
    pub request_projection: Vec<u8>,
    pub at_ms: i64,
}

pub async fn reserve_paid_image_plan(
    db: &Db,
    plan: PaidImagePlan,
) -> anyhow::Result<SpendReservation> {
    db.reserve_image_spend(
        plan.reservation_id,
        plan.scopes,
        plan.attempts,
        plan.policy_version,
        plan.created_at_ms,
    )
    .await
}

pub async fn preflight_and_dispatch_paid_image(
    db: &Db,
    provider: &dyn PaidImageProvider,
    request: PaidImageDispatch,
) -> anyhow::Result<ImageSpendDispatchEvidence> {
    let PaidImageDispatch {
        plan,
        attempt_id,
        session_id,
        idempotency_key,
        request_projection,
        at_ms,
    } = request;
    let reservation_id = plan.reservation_id.clone();
    let journal = PrepareExternalOperation {
        operation_kind: ExternalJournalToken::parse("image_generation")?,
        owner_session_id: ExternalJournalToken::parse(&session_id)?,
        idempotency_key: ExternalJournalToken::parse(&idempotency_key)?,
        payload_digest: ExternalJournalDigest::of(&request_projection),
        payload_len: request_projection.len(),
        provider_idempotency: None,
    };
    let (_, prepared) = db
        .reserve_and_prepare_image_spend(ReserveAndPrepareImageSpend {
            reservation_id: plan.reservation_id,
            keys: plan.scopes,
            attempts: plan.attempts,
            expected_policy_version: plan.policy_version,
            attempt_id: attempt_id.clone(),
            journal,
            created_at_ms: plan.created_at_ms,
        })
        .await?;
    dispatch_prepared_attempt(db, provider, reservation_id, attempt_id, prepared, at_ms).await
}

async fn dispatch_prepared_attempt(
    db: &Db,
    provider: &dyn PaidImageProvider,
    reservation_id: String,
    attempt_id: String,
    prepared: cockpit_db::db::external_journal::ExternalJournalRecord,
    at_ms: i64,
) -> anyhow::Result<ImageSpendDispatchEvidence> {
    let dispatching = db
        .begin_image_spend_dispatch(
            reservation_id.clone(),
            attempt_id.clone(),
            prepared.operation_id,
            prepared.version,
            at_ms,
        )
        .await?;
    let handoff = provider.handoff(&attempt_id).await;
    let evidence = match &handoff {
        Ok(evidence) => *evidence,
        Err(_) => ImageSpendDispatchEvidence::SubmissionUnknown,
    };
    db.finish_image_spend_dispatch(
        reservation_id,
        attempt_id,
        prepared.operation_id,
        dispatching.record().version,
        evidence,
        at_ms,
    )
    .await?;
    handoff.map(|_| evidence)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct FakeProvider(AtomicUsize);
    impl PaidImageProvider for FakeProvider {
        fn handoff<'a>(
            &'a self,
            _: &'a str,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<ImageSpendDispatchEvidence>> + Send + 'a>>
        {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(ImageSpendDispatchEvidence::Accepted) })
        }
    }

    struct FailingProvider;
    impl PaidImageProvider for FailingProvider {
        fn handoff<'a>(
            &'a self,
            _: &'a str,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<ImageSpendDispatchEvidence>> + Send + 'a>>
        {
            Box::pin(async { anyhow::bail!("transport outcome is unknown") })
        }
    }

    #[tokio::test]
    async fn paid_provider_cannot_run_before_successful_reservation() {
        let db = Db::open_in_memory().unwrap();
        let provider = FakeProvider(AtomicUsize::new(0));
        let result = preflight_and_dispatch_paid_image(
            &db,
            &provider,
            PaidImageDispatch {
                plan: PaidImagePlan {
                    reservation_id: "reservation".into(),
                    scopes: SpendScopeKeys {
                        plan_digest: "plan".into(),
                        session_id: "session".into(),
                        project_key: "project".into(),
                    },
                    attempts: vec![AttemptMaximum {
                        attempt_id: "attempt".into(),
                        usd_micros: Some(1),
                    }],
                    policy_version: 1,
                    created_at_ms: 0,
                },
                attempt_id: "attempt".into(),
                session_id: "session".into(),
                idempotency_key: "idempotency".into(),
                request_projection: b"redacted projection".to_vec(),
                at_ms: 0,
            },
        )
        .await;
        assert!(result.is_err());
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provider_handoff_error_is_durably_submission_unknown() {
        use cockpit_db::db::image_spend::{BudgetPolicy, ImageSpendSettings, ProjectEpochPolicy};
        let db = Db::open_in_memory().unwrap();
        db.save_image_spend_policy(
            "project".into(),
            ImageSpendSettings {
                request: BudgetPolicy::Finite { usd_micros: 10 },
                session: BudgetPolicy::Finite { usd_micros: 10 },
                project: BudgetPolicy::Finite { usd_micros: 10 },
                project_epoch: Some(ProjectEpochPolicy::CalendarMonth {
                    time_zone: "America/Chicago".into(),
                }),
            },
            None,
            0,
        )
        .await
        .unwrap();
        let result = preflight_and_dispatch_paid_image(
            &db,
            &FailingProvider,
            PaidImageDispatch {
                plan: PaidImagePlan {
                    reservation_id: "failed".into(),
                    scopes: SpendScopeKeys {
                        plan_digest: "plan".into(),
                        session_id: "session".into(),
                        project_key: "project".into(),
                    },
                    attempts: vec![AttemptMaximum {
                        attempt_id: "attempt".into(),
                        usd_micros: Some(1),
                    }],
                    policy_version: 1,
                    created_at_ms: 0,
                },
                attempt_id: "attempt".into(),
                session_id: "session".into(),
                idempotency_key: "failure-key".into(),
                request_projection: b"projection".to_vec(),
                at_ms: 1,
            },
        )
        .await;
        assert!(result.is_err());
        let record = db
            .external_operation_by_identity(
                &ExternalJournalToken::parse("image_generation").unwrap(),
                &ExternalJournalToken::parse("session").unwrap(),
                &ExternalJournalToken::parse("failure-key").unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            record.state,
            cockpit_db::db::external_journal::ExternalJournalState::SubmissionUnknown
        );
    }
}
