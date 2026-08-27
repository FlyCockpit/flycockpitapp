//! Verification inference through the same durable-before-handoff barrier as
//! an ordinary agent turn. Candidate bodies remain private, but every provider
//! request has a normal immutable inference row and external-journal ticket.

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::db::session_log::{
    InferenceAttemptMeta, InferencePhaseTimings, InferenceRequestStatus, SessionEventKind,
};
use crate::engine::agent::{
    InferenceOutcomeRecord, TurnEvent, prepare_inference_journal, record_inference_outcome,
    settle_inference_journal_error, settle_inference_journal_success,
};
use crate::engine::message::{AssistantContent, Message, ToolDefinition};
use crate::engine::model::{Model, ModelParams, UtilityCallSite};
use crate::session::{Session, SessionEventModelFrame};

pub(crate) struct VerificationInferenceInput<'a> {
    pub session: Arc<Session>,
    pub model: &'a Model,
    pub config: &'a crate::daemon::session_worker::SessionConfigHandle,
    pub system: &'a str,
    pub history: &'a [Message],
    pub prompt: &'a str,
    pub tools: &'a [ToolDefinition],
    pub params: ModelParams,
    pub agent_name: &'a str,
    pub site: UtilityCallSite,
    pub cancel: &'a tokio_util::sync::CancellationToken,
    /// Optional caller-owned absolute deadline. The inference barrier owns
    /// the timeout so a deadline cannot drop a provider future while leaving
    /// either audit journal pending.
    pub deadline_unix_ms: Option<i64>,
}

pub(crate) async fn journaled_verification_inference(
    input: VerificationInferenceInput<'_>,
) -> Result<Vec<AssistantContent>> {
    let call_id = Uuid::now_v7();
    let ordinal = 0;
    let mut params = input.params;
    params.max_tokens = Some(
        params
            .max_tokens
            .unwrap_or(crate::engine::model::UTILITY_MAX_TOKENS_CAP)
            .min(crate::engine::model::UTILITY_MAX_TOKENS_CAP),
    );
    params.tools_required = true;
    if input.site.pins_temperature_zero() {
        params.temperature = Some(0.0);
    }
    let prompt = Message::user(input.prompt);
    let payload = input.model.assemble_dispatch_request(
        input.system,
        input.history,
        &prompt,
        input.tools,
        &params,
    )?;
    let mut journal =
        prepare_inference_journal(&input.session, input.model, &payload, call_id, ordinal).await?;
    let table = input.model.session_redact_table();
    let primary_failed = input
        .session
        .insert_inference_attempt(
            call_id,
            ordinal,
            &payload,
            InferenceAttemptMeta {
                provider: Some(input.model.provider_id()),
                model: Some(input.model.model_id_ref()),
                trust: Some(if input.model.is_trusted() {
                    "trusted"
                } else {
                    "untrusted"
                }),
            },
            None,
            table.as_ref(),
            input.model.is_trusted(),
        )
        .await
        .is_err();
    if primary_failed && journal.is_none() {
        anyhow::bail!(
            "inference audit unavailable: primary audit write failed and no durable journal is installed; provider handoff refused"
        );
    }

    let timeout = input
        .deadline_unix_ms
        .map_or(input.site.timeout(), |deadline| {
            let remaining = deadline.saturating_sub(chrono::Utc::now().timestamp_millis());
            input.site.timeout().min(std::time::Duration::from_millis(
                u64::try_from(remaining.max(0)).unwrap_or_default(),
            ))
        });
    let started = std::time::Instant::now();
    let completion = match tokio::time::timeout(
        timeout,
        input.model.complete_captured(
            input.system,
            input.history,
            prompt,
            input.tools,
            params,
            input.agent_name,
            None,
            input.cancel,
            None,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::Error::new(crate::engine::model::InferenceFailure {
            provider: input.model.provider_id().to_string(),
            model: input.model.model_id_ref().to_string(),
            phase: "verification_dispatch".to_string(),
            class: crate::engine::model::InferenceErrorClass::UtilityTimeout,
            elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            retry_attempts: 1,
            detail: format!(
                "{:?} verification request exceeded its {}ms effective deadline",
                input.site,
                timeout.as_millis()
            ),
            observed_status: None,
            recovery: crate::engine::model::ProviderRecoverySignal::None,
        })),
    };

    let ((_, choice, usage), _, timing) = match completion {
        Ok(completion) => completion,
        Err(error) => {
            let (tx, _rx) = mpsc::channel::<TurnEvent>(1);
            record_inference_outcome(
                InferenceOutcomeRecord {
                    session: input.session.clone(),
                    call_id,
                    ordinal,
                    agent_name: input.agent_name,
                    wire_api: input.model.wire_api_label(),
                    routing_metadata: input.model.routing_metadata_json(None),
                    emit_inference_error_ui: false,
                    goal_provenance: None,
                    tx: &tx,
                },
                &error,
            )
            .await;
            settle_inference_journal_error(&mut journal, &error).await;
            return Err(error);
        }
    };
    if input
        .session
        .advance_inference_request(
            call_id,
            ordinal,
            InferenceRequestStatus::Completed,
            InferencePhaseTimings {
                first_token_ms: timing.first_token_ms.map(|value| value as i64),
                completed_ms: Some(timing.completed_ms as i64),
                failed_ms: None,
            },
        )
        .await
        .is_err()
    {
        tracing::warn!("primary verification inference audit terminal write failed");
    }
    if !settle_inference_journal_success(&mut journal).await {
        tracing::warn!("verification inference journal reconciliation failed");
    }
    if let Err(error) = input
        .session
        .record_event_with_model_frame(
            SessionEventKind::InferenceRequest,
            Some(input.agent_name),
            Some(&call_id.to_string()),
            SessionEventModelFrame {
                provider_id: input.model.provider_id(),
                model_id: input.model.model_id_ref(),
                config: input.config,
                session_table: table.as_ref(),
            },
            &serde_json::json!({
                "usage": usage.map(|usage| serde_json::json!({
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "cached_input_tokens": usage.cached_input_tokens,
                    "cache_creation_input_tokens": usage.cache_creation_input_tokens,
                })),
                "routing": input.model.routing_metadata_json(None),
                "ordinal": ordinal,
                "utility": match input.site {
                    UtilityCallSite::VerificationVariant => "verification_variant",
                    UtilityCallSite::VerificationAdjudication => "verification_adjudication",
                    _ => "verification_investigation",
                },
            }),
        )
        .await
    {
        tracing::warn!(%error, "record verification inference_request event failed");
    }
    Ok(choice)
}
