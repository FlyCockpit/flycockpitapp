//! Verification inference through the same durable-before-handoff barrier as
//! an ordinary agent turn. Candidate bodies remain private, but every provider
//! request has a normal immutable inference row and external-journal ticket.
//! Verification rows store a digest-only audit projection because raw
//! candidate bodies are intentionally non-durable.

use std::sync::{Arc, atomic::AtomicBool};

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
use crate::engine::message::{AssistantContent, Message, ToolDefinition, collect_tool_calls};
use crate::engine::model::{Model, ModelParams, UtilityCallSite};
use crate::session::{Session, SessionEventModelFrame};

fn verification_audit_projection(
    provider_payload: &serde_json::Value,
    site: UtilityCallSite,
    history_len: usize,
    tool_count: usize,
) -> Result<serde_json::Value> {
    let encoded = serde_json::to_vec(provider_payload)?;
    let classification = match site {
        UtilityCallSite::VerificationVariant => "verification_variant",
        UtilityCallSite::VerificationAdjudication => "verification_adjudication",
        _ => "verification_investigation",
    };
    Ok(serde_json::json!({
        "projection": "verification_inference_v1",
        "classification": classification,
        "request_digest": crate::db::verification_ledger::VerificationDigest::of(&encoded).as_str(),
        "history_message_count": history_len,
        "tool_definition_count": tool_count,
    }))
}

pub(crate) struct VerificationInferenceInput<'a> {
    pub session: Arc<Session>,
    pub model: &'a Model,
    pub config: &'a crate::daemon::session_worker::SessionConfigHandle,
    pub interrupts: &'a crate::engine::interrupt::InterruptHub,
    pub system: &'a str,
    pub history: &'a [Message],
    pub prompt: &'a str,
    pub tools: &'a [ToolDefinition],
    pub params: ModelParams,
    pub agent_name: &'a str,
    pub site: UtilityCallSite,
    pub cancel: &'a tokio_util::sync::CancellationToken,
    /// Set at the model's irreversible provider-stream handoff. Callers which
    /// need to distinguish a pre-dispatch refusal from a provider inference
    /// attempt use this only as an execution fact, never as an outcome signal.
    pub provider_handoff: Option<&'a AtomicBool>,
    /// Optional caller-owned absolute deadline. The inference barrier owns
    /// the timeout so a deadline cannot drop a provider future while leaving
    /// either audit journal pending.
    pub deadline_unix_ms: Option<i64>,
}

/// Build the exact untrusted safety surface used by verification requests.
///
/// Keeping this materialization separate makes the pre-dispatch budget
/// estimate use the same system prompt and tool definitions as the provider
/// handoff below. The boolean is the single eligibility predicate used again
/// when classifying the response through the sensitive-turn barrier.
pub(crate) fn effective_verification_route(
    system: &str,
    model: &Model,
    tools: &[ToolDefinition],
) -> (String, Vec<ToolDefinition>, bool) {
    effective_verification_route_for_trust(system, model.is_trusted(), tools)
}

fn effective_verification_route_for_trust(
    system: &str,
    model_is_trusted: bool,
    tools: &[ToolDefinition],
) -> (String, Vec<ToolDefinition>, bool) {
    let mut system = system.to_string();
    crate::engine::builtin::append_untrusted_leak_report_steering(&mut system, model_is_trusted);
    let mut tools = tools.to_vec();
    let report_leak_eligible =
        crate::leak_report::route_advertises_report_leak(model_is_trusted, &tools);
    if report_leak_eligible {
        tools.push(crate::leak_report::report_leak_tool_definition());
    }
    (system, tools, report_leak_eligible)
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
    let (system, tools, report_leak_eligible) =
        effective_verification_route(input.system, input.model, input.tools);
    let prompt = Message::user(input.prompt);
    let payload =
        input
            .model
            .assemble_dispatch_request(&system, input.history, &prompt, &tools, &params)?;
    // Verification prompts intentionally contain raw candidate args and
    // critiques. They are provider-visible but must never become an ordinary
    // inference payload row or a protected-redaction-history literal. The
    // normal durable-before-handoff barrier receives this digest-only audit
    // projection; the provider call below still receives the raw inputs.
    let audit_projection =
        verification_audit_projection(&payload, input.site, input.history.len(), tools.len())?;
    let mut journal = prepare_inference_journal(
        &input.session,
        input.model,
        &audit_projection,
        call_id,
        ordinal,
    )
    .await?;
    let table = input.model.session_redact_table();
    let primary_failed = input
        .session
        .insert_inference_attempt(
            call_id,
            ordinal,
            &audit_projection,
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
    let completion = match tokio::time::timeout(timeout, async {
        match input.provider_handoff {
            Some(provider_handoff) => {
                input
                    .model
                    .complete_captured_with_provider_handoff(
                        &system,
                        input.history,
                        prompt,
                        &tools,
                        params,
                        input.agent_name,
                        None,
                        input.cancel,
                        None,
                        provider_handoff,
                    )
                    .await
            }
            None => {
                input
                    .model
                    .complete_captured(
                        &system,
                        input.history,
                        prompt,
                        &tools,
                        params,
                        input.agent_name,
                        None,
                        input.cancel,
                        None,
                    )
                    .await
            }
        }
    })
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

    let ((_, mut choice, usage), _, timing) = match completion {
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
    let buffered_calls = collect_tool_calls(&choice);
    if crate::engine::agent::sensitive_turn::sensitive_turn_engages(
        report_leak_eligible,
        &buffered_calls,
    ) {
        let key_resolver = input.session.redaction_key_resolver().clone();
        let host = crate::engine::agent::sensitive_turn::LiveSensitiveContainmentHost {
            db: &input.session.db,
            key_resolver: key_resolver.as_ref(),
            interrupts: input.interrupts,
            session: input.session.as_ref(),
            provenance: crate::db::protected_leak_records::LeakProvenance {
                provider_id: Some(input.model.provider_id().to_owned()),
                model_id: Some(input.model.model_id_ref().to_owned()),
                generation: None,
                connector_id: None,
            },
            session_id: input.session.id.to_string(),
            now_ms: chrono::Utc::now().timestamp_millis(),
        };
        let outcome =
            crate::engine::agent::sensitive_turn::run_sensitive_turn_barrier(&host, buffered_calls)
                .await;
        for result in outcome.sensitive_results {
            tracing::info!(
                target: "engine",
                agent = input.agent_name,
                state = ?outcome.state,
                outcome = %result.model_output,
                "verification report_leak containment barrier classified the turn"
            );
        }
        choice.clear();
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

#[cfg(test)]
mod tests {
    use super::*;

    const CANDIDATE_SENTINEL: &str = "candidate-body-S3NT1N3L-must-not-persist";

    #[test]
    fn untrusted_verification_route_adds_leak_steering_and_containment_tool() {
        let original = ToolDefinition {
            name: "verification_candidate".to_string(),
            description: "return a candidate".to_string(),
            parameters: serde_json::json!({"type": "object"}),
        };
        let (system, tools, eligible) =
            effective_verification_route_for_trust("verification system", false, &[original]);

        assert!(eligible);
        assert!(system.contains("`report_leak`"));
        assert!(system.contains("base64"));
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[1].name, crate::leak_report::REPORT_LEAK_TOOL);
    }

    #[test]
    fn trusted_verification_route_does_not_advertise_leak_containment() {
        let original = ToolDefinition {
            name: "verification_candidate".to_string(),
            description: "return a candidate".to_string(),
            parameters: serde_json::json!({"type": "object"}),
        };
        let (system, tools, eligible) = effective_verification_route_for_trust(
            "verification system",
            true,
            &[original.clone()],
        );

        assert!(!eligible);
        assert_eq!(system, "verification system");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, original.name);
        assert_eq!(tools[0].description, original.description);
        assert_eq!(tools[0].parameters, original.parameters);
    }

    #[test]
    fn verification_audit_projection_contains_only_classification_digest_and_counts() {
        let raw = serde_json::json!({
            "prompt": {
                "candidates": [{
                    "args": {"content": CANDIDATE_SENTINEL},
                    "critique": format!("do not persist {CANDIDATE_SENTINEL}"),
                }]
            }
        });
        let projected =
            verification_audit_projection(&raw, UtilityCallSite::VerificationAdjudication, 0, 1)
                .unwrap();
        let encoded = serde_json::to_string(&projected).unwrap();
        assert!(!encoded.contains(CANDIDATE_SENTINEL));
        assert_eq!(projected["projection"], "verification_inference_v1");
        assert_eq!(projected["classification"], "verification_adjudication");
        assert_eq!(projected["request_digest"].as_str().unwrap().len(), 64);
    }

    #[tokio::test]
    async fn candidate_body_is_absent_from_durable_request_and_protected_history() {
        let root = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open_in_memory().unwrap();
        let session = Session::create_for_test(
            db.clone(),
            root.path().to_path_buf(),
            "Build",
            crate::session::test_redaction_key_resolver(),
        )
        .unwrap();
        let redact_config = crate::config::extended::RedactConfig {
            enabled: true,
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: false,
            min_secret_length: 4,
            ..crate::config::extended::RedactConfig::default()
        };
        let table = crate::redact::RedactionTable::build_with_env_and_secrets(
            &redact_config,
            root.path(),
            &std::collections::HashMap::from([(
                "CANDIDATE_SENTINEL".to_string(),
                CANDIDATE_SENTINEL.to_string(),
            )]),
            Vec::<(String, String)>::new(),
        )
        .unwrap();
        let raw = serde_json::json!({
            "prompt": {
                "candidate_args": {"content": CANDIDATE_SENTINEL},
                "candidate_critique": format!("critique: {CANDIDATE_SENTINEL}"),
            },
        });
        let projection =
            verification_audit_projection(&raw, UtilityCallSite::VerificationAdjudication, 0, 1)
                .unwrap();
        let call_id = Uuid::now_v7();
        session
            .insert_inference_attempt(
                call_id,
                0,
                &projection,
                InferenceAttemptMeta::default(),
                None,
                &table,
                true,
            )
            .await
            .unwrap();
        let stored = db
            .get_inference_request(&call_id.to_string(), 0)
            .await
            .unwrap()
            .expect("verification inference audit row");
        assert!(!stored.payload.to_string().contains(CANDIDATE_SENTINEL));
        assert!(
            db.protected_redaction_history_list(&session.id.to_string())
                .await
                .unwrap()
                .is_empty(),
            "verification candidate bodies must not enter protected history"
        );
    }
}
