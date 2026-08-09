use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{server::DaemonContext, session_worker::SessionWork};

const CONSUMER: &str = "daemon_effect_v1";
const LEASE_MS: i64 = 30_000;
const EFFECT_KINDS: &[&str] = &[
    "create_goal",
    "set_goal_status",
    "clear_goal",
    "cancel_paused_work",
    "cancel_run_invocation",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteSessionEffectV1 {
    pub schema_version: u8,
    pub session_id: Uuid,
}

pub(crate) fn spawn_background(ctx: Arc<DaemonContext>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut idle = Duration::from_millis(25);
        loop {
            let mut progressed = false;
            for kind in EFFECT_KINDS {
                match drain_kind_once(&ctx, kind).await {
                    Ok(true) => progressed = true,
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, outbox_kind = *kind, "remote outbox effect delivery failed")
                    }
                }
            }
            idle = if progressed {
                Duration::from_millis(25)
            } else {
                (idle * 2).min(Duration::from_secs(5))
            };
            tokio::time::sleep(idle).await;
        }
    })
}

pub(crate) async fn drain_kind_once(ctx: &Arc<DaemonContext>, kind: &str) -> Result<bool> {
    if !EFFECT_KINDS.contains(&kind) {
        bail!("unknown remote effect outbox kind");
    }
    let now = chrono::Utc::now().timestamp_millis();
    let Some(lease) = ctx
        .db
        .claim_remote_outbox_delivery(CONSUMER, kind, None, None, now, LEASE_MS)
        .await?
    else {
        return Ok(false);
    };
    deliver(ctx, &lease.kind, &lease.canonical_payload).await?;
    let acked = ctx
        .db
        .ack_remote_outbox_delivery(
            &lease.logical_attachment_id,
            &lease.delivery_id,
            CONSUMER,
            &lease.lease_id,
            chrono::Utc::now().timestamp_millis(),
        )
        .await?;
    if !acked {
        bail!("remote outbox effect lease expired before acknowledgement");
    }
    Ok(true)
}

async fn deliver(ctx: &Arc<DaemonContext>, kind: &str, payload: &[u8]) -> Result<()> {
    match kind {
        "create_goal" | "set_goal_status" => {
            let receipt: cockpit_proto::RemoteGoalOutcomeV1 =
                serde_json::from_slice(payload).context("decoding remote goal effect")?;
            if receipt.schema_version != 1 {
                bail!("unsupported remote goal effect schema");
            }
            if let Some(handle) = ctx.registry.live_handle(receipt.session_id) {
                handle.send_work(SessionWork::WakeGoal).await?;
            }
        }
        "clear_goal" => {
            let effect: RemoteSessionEffectV1 =
                serde_json::from_slice(payload).context("decoding clear-goal effect")?;
            if effect.schema_version != 1 {
                bail!("unsupported session effect schema");
            }
            if let Some(handle) = ctx.registry.live_handle(effect.session_id) {
                handle.send_work(SessionWork::WakeGoal).await?;
            }
        }
        "cancel_paused_work" => {
            let effect: RemoteSessionEffectV1 =
                serde_json::from_slice(payload).context("decoding paused-work effect")?;
            if effect.schema_version != 1 {
                bail!("unsupported session effect schema");
            }
            ctx.registry
                .locks()
                .suspend_session(effect.session_id)
                .await?;
        }
        "cancel_run_invocation" => {
            let receipt: cockpit_proto::RunInvocationCancelResultV1 =
                serde_json::from_slice(payload).context("decoding invocation-cancel effect")?;
            if receipt.schema_version != cockpit_proto::RunInvocationCancelResultV1::SCHEMA_VERSION
            {
                bail!("unsupported invocation-cancel effect schema");
            }
            // Cancellation is already authoritative in SQLite. A live worker
            // observes that state at its next dispatch boundary; no duplicate
            // non-idempotent action is necessary after restart.
        }
        _ => bail!("unknown remote effect outbox kind"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::remote_attachment_operations::{
        CommitRemoteOperation, RemoteOperationClass, ReserveRemoteOperation,
    };

    #[tokio::test]
    async fn committed_effect_is_drained_once_and_unknown_kind_is_untouched() {
        let ctx = crate::daemon::server::tests::test_ctx();
        let attachment = "00000000-0000-4000-8000-000000000071";
        let operation = "01890f3e-4c00-7000-8000-000000000072";
        ctx.db
            .reserve_remote_attachment_operation(ReserveRemoteOperation {
                logical_attachment_id: attachment,
                operation_id: operation,
                authenticated_device_id: "00000000-0000-4000-8000-000000000073",
                authenticated_device_generation: 1,
                operation_class: RemoteOperationClass::TransactionalMutation,
                request_hash: [7; 32],
                now_ms: 1,
            })
            .await
            .unwrap();
        let receipt = cockpit_proto::RunInvocationCancelResultV1 {
            schema_version: cockpit_proto::RunInvocationCancelResultV1::SCHEMA_VERSION,
            client_submission_id: Uuid::new_v4(),
            outcome: cockpit_proto::RunInvocationCancelOutcome::NotFound,
            state: cockpit_proto::RunInvocationLifecycleState::NotFound,
            state_version: 0,
        };
        let payload = serde_json::to_vec(&receipt).unwrap();
        ctx.db
            .commit_remote_attachment_operation(CommitRemoteOperation {
                logical_attachment_id: attachment,
                operation_id: operation,
                safe_response: &payload,
                outbox_delivery_id: "00000000-0000-4000-8000-000000000074",
                outbox_kind: "cancel_run_invocation",
                outbox_payload: &payload,
                now_ms: 2,
            })
            .await
            .unwrap();
        assert!(
            drain_kind_once(&ctx, "cancel_run_invocation")
                .await
                .unwrap()
        );
        assert!(
            !drain_kind_once(&ctx, "cancel_run_invocation")
                .await
                .unwrap()
        );
        assert!(drain_kind_once(&ctx, "unregistered_kind").await.is_err());

        let poison_operation = "01890f3e-4c00-7000-8000-000000000075";
        ctx.db
            .reserve_remote_attachment_operation(ReserveRemoteOperation {
                logical_attachment_id: attachment,
                operation_id: poison_operation,
                authenticated_device_id: "00000000-0000-4000-8000-000000000073",
                authenticated_device_generation: 1,
                operation_class: RemoteOperationClass::TransactionalMutation,
                request_hash: [8; 32],
                now_ms: 3,
            })
            .await
            .unwrap();
        ctx.db
            .commit_remote_attachment_operation(CommitRemoteOperation {
                logical_attachment_id: attachment,
                operation_id: poison_operation,
                safe_response: b"ack",
                outbox_delivery_id: "00000000-0000-4000-8000-000000000076",
                outbox_kind: "cancel_run_invocation",
                outbox_payload: b"not-json",
                now_ms: 4,
            })
            .await
            .unwrap();
        assert!(
            drain_kind_once(&ctx, "cancel_run_invocation")
                .await
                .is_err()
        );
        let reclaimed = ctx
            .db
            .claim_remote_outbox_delivery(
                CONSUMER,
                "cancel_run_invocation",
                None,
                None,
                chrono::Utc::now().timestamp_millis() + LEASE_MS + 1,
                LEASE_MS,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reclaimed.attempts, 2,
            "poison is retained for bounded retry"
        );
    }
}
