pub use cockpit_proto::command;
pub use cockpit_proto::*;

use crate::engine::TurnEvent;
use uuid::Uuid;

/// Convert a single engine `TurnEvent` into one or more wire
/// `proto::Event`s. Some events (e.g. `ThinkingStarted`) map 1:1;
/// others (subagent spawn / report) are kept as the natural-enough
/// proto equivalents. Returning a `Vec` keeps the door open for a
/// 1:N expansion when, e.g., we attach a recovery chip alongside a
/// `ToolEnd` in the future.
pub(crate) fn turn_event_to_proto(event: TurnEvent, session_id: Uuid) -> Vec<Event> {
    match event {
        TurnEvent::InterruptDecision {
            session_id: _,
            interrupt_id,
            decision,
            seq,
        } => vec![Event::InterruptResolved {
            session_id,
            interrupt_id,
            decision: Some(decision),
            seq,
        }],
        TurnEvent::InterruptQueueChanged {
            session_id: _,
            active_interrupt_id,
            pending_count,
        } => vec![Event::InterruptQueueChanged {
            session_id,
            active_interrupt_id,
            pending_count,
        }],
        TurnEvent::ThinkingStarted { agent, turn_id } => {
            vec![Event::ThinkingStarted {
                session_id,
                agent,
                turn_id,
            }]
        }
        TurnEvent::Reconnecting {
            agent,
            attempt,
            provider,
            model,
            url,
        } => {
            vec![Event::Reconnecting {
                session_id,
                agent,
                attempt,
                provider,
                model,
                url,
            }]
        }
        TurnEvent::DaemonLinkReconnecting { .. }
        | TurnEvent::DaemonLinkReconnected
        | TurnEvent::DaemonLinkTerminal { .. }
        | TurnEvent::PausedWorkAvailable { .. }
        | TurnEvent::ResumeRepairRequired { .. }
        | TurnEvent::HistoryReplay { .. } => vec![],
        TurnEvent::AssistantTextDelta { agent, delta } => {
            vec![Event::AssistantTextDelta {
                session_id,
                agent,
                delta,
            }]
        }
        TurnEvent::ReasoningDelta { agent, delta } => {
            vec![Event::ReasoningDelta {
                session_id,
                agent,
                delta,
            }]
        }
        TurnEvent::AssistantText {
            agent,
            text,
            reasoning,
            seq,
        } => {
            vec![Event::AssistantText {
                session_id,
                agent,
                text,
                reasoning,
                seq,
            }]
        }
        TurnEvent::UserMessageRecorded {
            seq,
            preflight_cleaned,
        } => {
            vec![Event::UserMessageRecorded {
                session_id,
                seq,
                preflight_cleaned,
            }]
        }
        TurnEvent::QueuedUserMessagesFolded {
            text,
            display_text,
            tag_expansions,
            queue_item_ids,
            target,
            seq,
            preflight_cleaned,
        } => {
            vec![Event::QueuedUserMessagesFolded {
                session_id,
                text,
                display_text,
                tag_expansions,
                queue_item_ids,
                target: queue_target_to_proto(target),
                seq,
                preflight_cleaned,
            }]
        }
        TurnEvent::SessionPersistFailed { error } => {
            vec![Event::SessionPersistFailed { session_id, error }]
        }
        TurnEvent::SessionDriverFailed { error } => {
            vec![Event::SessionDriverFailed { session_id, error }]
        }
        TurnEvent::UserMessageDispatchFailed { .. } => vec![],
        TurnEvent::PreflightStarted => {
            vec![Event::PreflightStarted { session_id }]
        }
        TurnEvent::UserMessageRetracted => {
            vec![Event::UserMessageRetracted { session_id }]
        }
        TurnEvent::Notice { text } => {
            vec![Event::Notice { session_id, text }]
        }
        TurnEvent::SkillAutoInjected { name, reason } => {
            vec![Event::SkillAutoInjected {
                session_id,
                name,
                reason,
            }]
        }
        TurnEvent::ToolStart {
            agent,
            call_id,
            tool,
            args,
        } => vec![Event::ToolStart {
            session_id,
            agent,
            call_id,
            tool,
            args,
        }],
        TurnEvent::ToolEnd {
            agent,
            call_id,
            tool,
            output,
            truncated,
            seq,
            hint,
        } => vec![Event::ToolEnd {
            session_id,
            agent,
            call_id,
            tool,
            output,
            truncated,
            seq,
            hint,
        }],
        TurnEvent::ResourceWait {
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
        } => vec![Event::ResourceWait {
            session_id,
            agent,
            request_id,
            display_id,
            resources,
            queue_position,
            command_label,
        }],
        TurnEvent::ResourceStart {
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
        } => vec![Event::ResourceStart {
            session_id,
            agent,
            request_id,
            display_id,
            resources,
            wait_ms,
            command_label,
        }],
        TurnEvent::ResourceClear {
            agent,
            request_id,
            display_id,
            resources,
            command_label,
        } => vec![Event::ResourceClear {
            session_id,
            agent,
            request_id,
            display_id,
            resources,
            command_label,
        }],
        TurnEvent::ToolError {
            agent,
            call_id,
            tool,
            error,
            kind,
            seq,
        } => vec![Event::ToolError {
            session_id,
            agent,
            call_id,
            tool,
            error,
            kind,
            seq,
        }],
        TurnEvent::InferenceFailed {
            agent,
            provider,
            model,
            error_class,
            detail,
            auth_failure,
        } => vec![Event::InferenceFailed {
            session_id,
            agent,
            provider,
            model,
            error_class,
            detail,
            auth_failure,
        }],
        TurnEvent::InferenceSucceeded { provider, model } => vec![Event::InferenceSucceeded {
            session_id,
            provider,
            model,
        }],
        TurnEvent::InferenceWarning {
            agent,
            provider,
            model,
            phase,
            waited_secs,
        } => vec![Event::InferenceWarning {
            session_id,
            agent,
            provider,
            model,
            phase,
            waited_secs,
        }],
        TurnEvent::BackupUsed {
            agent,
            primary_model,
            error_class,
            backup_model,
        } => vec![Event::BackupUsed {
            session_id,
            agent,
            primary_model,
            error_class,
            backup_model,
        }],
        TurnEvent::SubagentSpawned {
            parent,
            child,
            task_call_id,
            label,
            prompt,
            requested_cwd,
            resolved_cwd,
            trusted_only,
            model_trusted,
            routing,
        } => vec![Event::SubagentSpawned {
            session_id,
            parent,
            child,
            task_call_id,
            label,
            prompt,
            requested_cwd,
            resolved_cwd,
            trusted_only,
            model_trusted,
            routing,
        }],
        TurnEvent::SubagentRouting {
            task_call_id,
            label,
            child,
            provider,
            model,
            trusted_only,
            model_trusted,
            routing,
        } => vec![Event::SubagentRouting {
            session_id,
            task_call_id,
            label,
            child,
            provider,
            model,
            trusted_only,
            model_trusted,
            routing,
        }],
        TurnEvent::SubagentReport {
            agent,
            task_call_id,
            label,
            report,
            trusted_only,
            model_trusted,
            routing,
        } => {
            vec![Event::SubagentReport {
                session_id,
                agent,
                task_call_id,
                label,
                report,
                trusted_only,
                model_trusted,
                routing,
            }]
        }
        TurnEvent::NestedTurn {
            task_call_id,
            label,
            parent_task_call_id,
            inner,
        } => turn_event_to_proto(*inner, session_id)
            .into_iter()
            .map(|inner| Event::NestedTurn {
                session_id,
                task_call_id: task_call_id.clone(),
                label: label.clone(),
                parent_task_call_id: parent_task_call_id.clone(),
                inner: Box::new(inner),
            })
            .collect(),
        TurnEvent::Usage { agent, usage } => {
            vec![Event::Usage {
                session_id,
                agent,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
                cached_input_tokens: usage.cached_input_tokens,
                cache_creation_input_tokens: usage.cache_creation_input_tokens,
            }]
        }
        TurnEvent::AgentIdle { turn_id, reason } => {
            vec![Event::AgentIdle {
                session_id,
                turn_id,
                reason,
            }]
        }
        TurnEvent::PrimarySwapped { name } => {
            vec![Event::PrimarySwapped { session_id, name }]
        }
        TurnEvent::LlmModeChanged { mode } => {
            vec![Event::LlmModeChanged { session_id, mode }]
        }
        // Engine→proto direction never produces this — the `question`
        // tool emits `Event::InterruptRaised` directly through
        // the interrupt hub, and the TUI-client direction
        // (`proto_event_to_turn_event`) is the only place that
        // synthesizes the `TurnEvent` form. No wire event to forward.
        TurnEvent::InterruptRaised { .. } => vec![],
        TurnEvent::InterruptResolved { .. } => vec![],
        TurnEvent::ScheduleStarted {
            // The engine stamps the originating session; the worker's own
            // `session_id` is authoritative for the wire event and equals it.
            session_id: _,
            job_id,
            label,
            kind,
        } => vec![Event::ScheduleStarted {
            session_id,
            job_id,
            label,
            kind,
        }],
        TurnEvent::ScheduleProgress { job_id } => {
            vec![Event::ScheduleProgress { session_id, job_id }]
        }
        TurnEvent::ScheduleNote { job_id, text } => {
            vec![Event::ScheduleNote {
                session_id,
                job_id,
                text,
            }]
        }
        TurnEvent::ScheduleCompleted {
            job_id,
            label,
            kind,
            failed,
        } => vec![Event::ScheduleCompleted {
            session_id,
            job_id,
            label,
            kind,
            failed,
        }],
        TurnEvent::ContextProjection {
            prunable_tokens,
            cache_cold,
        } => {
            vec![Event::ContextProjection {
                session_id,
                prunable_tokens,
                cache_cold,
            }]
        }
        TurnEvent::Pruned {
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
        } => vec![Event::Pruned {
            session_id,
            auto,
            bodies,
            tokens_saved,
            elided,
            trigger_reason,
            cache_break,
        }],
        TurnEvent::CompactReady {
            new_session_id,
            handoff,
            brief,
            source,
            trigger_ctx_pct,
            tokens_before,
            tokens_after,
            turns_summarized,
            tail_kept,
            tail_trimmed,
            seed_tool_count,
            seed_tool_tokens,
        } => vec![Event::CompactReady {
            session_id,
            new_session_id,
            handoff,
            brief,
            source,
            trigger_ctx_pct,
            tokens_before,
            tokens_after,
            turns_summarized,
            tail_kept,
            tail_trimmed,
            seed_tool_count,
            seed_tool_tokens,
        }],
        // The engine never emits `SandboxState` — the daemon's
        // `SetSandbox` handler broadcasts the wire event directly (it
        // carries `session_id`). This arm exists only for exhaustiveness.
        TurnEvent::SandboxState {
            mode,
            container_network_enabled,
            container_availability,
        } => {
            vec![Event::SandboxState {
                session_id,
                mode,
                enabled: mode.enabled(),
                container_network_enabled,
                container_availability,
            }]
        }
        TurnEvent::SandboxEscalationState { enabled } => {
            vec![Event::SandboxEscalationState {
                session_id,
                enabled,
            }]
        }
        // Emitted by `engine::agent::turn` on the sandbox-unavailable refuse
        // path (§6.5). The mapping carries the remedy + session_id verbatim;
        // the per-session de-dupe (fire once per condition, not per failed
        // bash call) lives in the forward seam below, so a repeated failure
        // produces no second broadcast.
        TurnEvent::SandboxUnavailable {
            remedy,
            fix_command,
        } => vec![Event::SandboxUnavailable {
            session_id,
            remedy,
            fix_command,
        }],
        // The engine never emits `RedactionState` — the daemon's
        // `SetRedaction` handler broadcasts the wire event directly. This
        // arm exists only for exhaustiveness.
        TurnEvent::RedactionState {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
        } => {
            vec![Event::RedactionState {
                session_id,
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            }]
        }
        // Unlike redaction/sandbox, the DRIVER emits `PreflightState` — it
        // owns the session-only override + the toggle resolution (`/preflight`,
        // implementation note). Mapped to the broadcast event here.
        TurnEvent::PreflightState { enabled } => {
            vec![Event::PreflightState {
                session_id,
                enabled,
            }]
        }
        TurnEvent::TrustedOnlyState { enabled } => {
            vec![Event::TrustedOnlyState {
                session_id,
                enabled,
            }]
        }
        TurnEvent::ApprovalModeState { mode } => {
            vec![Event::ApprovalModeState { session_id, mode }]
        }
        TurnEvent::DelegationRecursionState {
            enabled,
            default_depth,
        } => {
            vec![Event::DelegationRecursionState {
                session_id,
                enabled,
                default_depth,
            }]
        }
        // The session gitignore-allowlist push is emitted directly over the
        // per-session bus — by the approval flow's `emit_gitignore_allow`
        // (`InterruptHub`) on change and by `broadcast_gitignore_allow` on
        // attach (implementation note). The engine
        // never routes it through the turn stream; this arm is for
        // exhaustiveness only.
        TurnEvent::GitignoreAllow { .. } => vec![],
        // The model-comparison tandem-set push is broadcast directly by the
        // `SetTandemModels` handler (`model-comparison-tandem-
        // inference.md`); the engine never routes it through the turn stream,
        // so this arm is for exhaustiveness only.
        TurnEvent::TandemState { .. } => vec![],
        // Caffeination is daemon-global, not a session event: the
        // `SetCaffeinate` handler / until-idle watcher broadcast
        // `Event::CaffeinateState` over the global bus directly.
        // The engine never emits this; the arm is for exhaustiveness.
        TurnEvent::CaffeinateState { .. } => vec![],
        // The drain notice is daemon-global, broadcast by the daemon's
        // graceful-shutdown path directly (`server::request_shutdown`); the
        // engine never emits it. This arm is for exhaustiveness only.
        TurnEvent::DaemonDraining { .. } => vec![],
        // A blocked/unblocked `readlock` (`readlock-wait-and-lock-expiry.md`):
        // emitted by the `readlock` tool through the per-turn event stream;
        // forwarded verbatim, scoped to this session so only its attached
        // clients show the transient waiting indicator.
        TurnEvent::WaitingForLock {
            path,
            holder_agent,
            waiting,
        } => vec![Event::WaitingForLock {
            session_id,
            path,
            holder_agent,
            waiting,
        }],
        TurnEvent::QueueUpdated { .. } => vec![],
        TurnEvent::ForegroundInputTarget { target } => vec![Event::ForegroundInputTarget {
            session_id,
            target: queue_target_to_proto(target),
        }],
        TurnEvent::ConnectorStatus { .. } => vec![],
    }
}

fn queue_target_to_proto(target: crate::engine::message::QueueTarget) -> QueueTarget {
    QueueTarget {
        id: target.id,
        agent: target.agent,
        depth: target.depth,
        task_call_id: target.task_call_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::agent::TurnEvent;
    use uuid::Uuid;

    #[test]
    fn subagent_routing_amend_roundtrips_through_proto() {
        let session_id = Uuid::new_v4();
        let routing = serde_json::json!({
            "provider": "test-provider",
            "resolved_model": "child-model",
            "fallback_decision": "backup",
            "location": "private_remote"
        });

        let out = turn_event_to_proto(
            TurnEvent::SubagentRouting {
                task_call_id: "task-1".to_string(),
                label: "second".to_string(),
                child: "explore".to_string(),
                provider: "test-provider".to_string(),
                model: "child-model".to_string(),
                trusted_only: true,
                model_trusted: false,
                routing: routing.clone(),
            },
            session_id,
        );

        match out.as_slice() {
            [
                Event::SubagentRouting {
                    session_id: actual_session_id,
                    task_call_id,
                    label,
                    child,
                    provider,
                    model,
                    trusted_only,
                    model_trusted,
                    routing: actual_routing,
                },
            ] => {
                assert_eq!(*actual_session_id, session_id);
                assert_eq!(task_call_id, "task-1");
                assert_eq!(label, "second");
                assert_eq!(child, "explore");
                assert_eq!(provider, "test-provider");
                assert_eq!(model, "child-model");
                assert!(*trusted_only);
                assert!(!*model_trusted);
                assert_eq!(actual_routing, &routing);
            }
            other => panic!("expected one SubagentRouting event, got {other:?}"),
        }
    }
}
