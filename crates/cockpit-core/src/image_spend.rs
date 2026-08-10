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
    AttemptMaximum, ImageSpendDispatchEvidence, SpendReservation, SpendScopeKeys,
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
    plan: PaidImagePlan,
    attempt_id: String,
    session_id: &str,
    idempotency_key: &str,
    request_projection: &[u8],
    at_ms: i64,
) -> anyhow::Result<ImageSpendDispatchEvidence> {
    let reservation_id = plan.reservation_id.clone();
    reserve_paid_image_plan(db, plan).await?;
    dispatch_reserved_attempt(
        db,
        provider,
        reservation_id,
        attempt_id,
        session_id,
        idempotency_key,
        request_projection,
        at_ms,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn dispatch_reserved_attempt(
    db: &Db,
    provider: &dyn PaidImageProvider,
    reservation_id: String,
    attempt_id: String,
    session_id: &str,
    idempotency_key: &str,
    request_projection: &[u8],
    at_ms: i64,
) -> anyhow::Result<ImageSpendDispatchEvidence> {
    let prepared = db
        .prepare_image_spend_dispatch(
            reservation_id.clone(),
            attempt_id.clone(),
            PrepareExternalOperation {
                operation_kind: ExternalJournalToken::parse("image_generation")?,
                owner_session_id: ExternalJournalToken::parse(session_id)?,
                idempotency_key: ExternalJournalToken::parse(idempotency_key)?,
                payload_digest: ExternalJournalDigest::of(request_projection),
                payload_len: request_projection.len(),
                provider_idempotency: None,
            },
            at_ms,
        )
        .await?;
    let dispatching = db
        .begin_image_spend_dispatch(
            reservation_id.clone(),
            attempt_id.clone(),
            prepared.operation_id,
            prepared.version,
            at_ms,
        )
        .await?;
    let evidence = provider.handoff(&attempt_id).await?;
    db.finish_image_spend_dispatch(
        reservation_id,
        attempt_id,
        prepared.operation_id,
        dispatching.record().version,
        evidence,
        at_ms,
    )
    .await?;
    Ok(evidence)
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

    #[tokio::test]
    async fn paid_provider_cannot_run_before_successful_reservation() {
        let db = Db::open_in_memory().unwrap();
        let provider = FakeProvider(AtomicUsize::new(0));
        let result = preflight_and_dispatch_paid_image(
            &db,
            &provider,
            PaidImagePlan {
                reservation_id: "reservation".into(),
                scopes: SpendScopeKeys {
                    plan_digest: "plan".into(),
                    session_id: "session".into(),
                    project_key: "project".into(),
                    project_epoch_sequence: 1,
                },
                attempts: vec![AttemptMaximum {
                    attempt_id: "attempt".into(),
                    usd_micros: Some(1),
                }],
                policy_version: 1,
                created_at_ms: 0,
            },
            "attempt".into(),
            "session",
            "idempotency",
            b"redacted projection",
            0,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(provider.0.load(Ordering::SeqCst), 0);
    }
}
