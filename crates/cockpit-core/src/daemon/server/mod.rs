//! Daemon server — accept loop + per-client task.
//!
//! Bound to the daemon's Unix socket. Each accepted connection spawns
//! a [`handle_client`] task that owns a [`ProtoStream`] and routes
//! requests to / forwards events from the [`SessionRegistry`].
//!
//! See `the design notes` §8 for the architecture and §8c for the wire-schema
//! contract that lets this layer ship without bikeshedding transport.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use uuid::Uuid;

use crate::config::extended::{DaemonUploadLimitsConfig, ExtendedConfig, RetentionConfig};
use crate::daemon::DaemonPaths;
use crate::daemon::config_source::ConfigSource;
use crate::daemon::principal::{self, ClientPrincipal, SessionAccess};
use crate::daemon::proto::{
    self, Body, Envelope, ErrorCode, ErrorPayload, ProtoStream, RecvFrame, Request, Response,
};
use crate::daemon::registry::SessionRegistry;
use crate::daemon::scheduler::DaemonSchedulerHandle;
use crate::daemon::session_worker::{SessionWork, SessionWorkerHandle};
use crate::daemon::shutdown::ShutdownPhase;
use crate::daemon::{
    EventEnvelope, EventReceiver, EventSender, SharedRedactionTable, current_redaction, send_event,
    set_current_redaction,
};
use crate::db::Db;
use crate::env_snapshot::{
    EnvDiffSummary, EnvDriftPolicy, EnvSnapshot, EnvSnapshotMeta, EnvSnapshotSource,
    EnvSnapshotWire, diff_summary,
};
use crate::locks::LockManager;
use crate::redact::RedactionTable;

/// Daemon-wide broadcast capacity for global (non-session) events such as
/// [`proto::Event::CaffeinateState`]. Generous — these are rare.
const GLOBAL_EVENT_CAPACITY: usize = 64;
const IN_PROCESS_REQUEST_QUEUE: usize = 64;
const IN_PROCESS_EVENT_QUEUE: usize = 1024;

static IN_PROCESS_CONTEXTS: OnceLock<StdMutex<HashMap<PathBuf, Weak<DaemonContext>>>> =
    OnceLock::new();

fn build_daemon_redaction_table() -> Arc<RedactionTable> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let cfg = ConfigSource::production()
        .load(&cwd)
        .map(|(_, extended)| extended.redact)
        .unwrap_or_default();
    Arc::new(RedactionTable::build(&cfg, &cwd).unwrap_or_else(|error| {
        tracing::warn!(error = %error, "building daemon redaction table failed");
        RedactionTable::empty()
    }))
}

fn refresh_global_redaction_table(shared: &SharedRedactionTable) -> Arc<RedactionTable> {
    let fresh = build_daemon_redaction_table();
    let table = match current_redaction(shared).union(&fresh) {
        Ok(table) => Arc::new(table),
        Err(error) => {
            tracing::warn!(error = %error, "unioning daemon redaction table failed");
            fresh
        }
    };
    set_current_redaction(shared, table.clone());
    table
}

fn scrub_json_strings(value: &mut serde_json::Value, redact: &RedactionTable) {
    match value {
        serde_json::Value::String(s) => {
            *s = redact.scrub(s);
        }
        serde_json::Value::Array(items) => {
            for item in items {
                scrub_json_strings(item, redact);
            }
        }
        serde_json::Value::Object(map) => {
            for value in map.values_mut() {
                scrub_json_strings(value, redact);
            }
        }
        _ => {}
    }
}

fn scrub_event_for_principal(
    principal: &ClientPrincipal,
    envelope: EventEnvelope,
) -> Option<proto::Event> {
    if principal.is_owner() {
        return Some(envelope.event);
    }
    scrub_proto_event(envelope.event, &envelope.redact)
}

fn scrub_proto_event(event: proto::Event, redact: &RedactionTable) -> Option<proto::Event> {
    let mut event = event;
    scrub_event_free_text(&mut event, redact);
    Some(event)
}

fn scrub_proto_response(
    response: proto::Response,
    redact: &RedactionTable,
) -> Option<proto::Response> {
    let mut response = response;
    scrub_response_free_text(&mut response, redact);
    Some(response)
}

fn scrub_history_for_principal(
    principal: &ClientPrincipal,
    history: Vec<proto::HistoryEntry>,
    redact: &RedactionTable,
) -> Vec<proto::HistoryEntry> {
    if principal.is_owner() {
        return history;
    }
    history
        .into_iter()
        .filter_map(|entry| scrub_history_entry(entry, redact))
        .collect()
}

fn scrub_history_entry(
    entry: proto::HistoryEntry,
    redact: &RedactionTable,
) -> Option<proto::HistoryEntry> {
    let mut entry = entry;
    scrub_history_entry_free_text(&mut entry, redact);
    Some(entry)
}

fn scrub_response_free_text(response: &mut proto::Response, redact: &RedactionTable) {
    match response {
        proto::Response::Ack => {}
        proto::Response::UserMessageQueued { item, queue } => {
            scrub_queue_item(item, redact);
            scrub_queue(queue, redact);
        }
        proto::Response::DelegationSteer { result } => {
            scrub_delegation_steer_result(result, redact)
        }
        proto::Response::AttachmentUploadStarted {
            upload_id: _,
            max_chunk_base64_bytes: _,
        }
        | proto::Response::AttachmentChunkAccepted {
            upload_id: _,
            next_offset: _,
        }
        | proto::Response::AttachmentUploaded { image_ref: _ }
        | proto::Response::NoteRecorded { seq: _ }
        | proto::Response::SessionLiveStatus { statuses: _ }
        | proto::Response::TerminalOpened {
            terminal_id: _,
            viewer_count: _,
            recording: _,
        }
        | proto::Response::FsWrite { hash: _ }
        | proto::Response::UsageCounts {
            models: _,
            slash: _,
            tags: _,
        }
        | proto::Response::SandboxState {
            mode: _,
            enabled: _,
            container_network_enabled: _,
            container_availability: _,
        }
        | proto::Response::SandboxEscalationState { enabled: _ }
        | proto::Response::RedactionState {
            scan_environment: _,
            scan_dotenv: _,
            scan_ssh_keys: _,
        }
        | proto::Response::PreflightState { enabled: _ }
        | proto::Response::TrustedOnlyState { enabled: _ }
        | proto::Response::ApprovalModeState { mode: _ }
        | proto::Response::DelegationRecursionState {
            enabled: _,
            default_depth: _,
        } => {}
        proto::Response::TerminalPasteImage {
            terminal_id: _,
            path,
        } => scrub_string(path, redact),
        proto::Response::RemoveQueuedUserMessageResult {
            applied: _,
            reason: _,
            removed_item,
            queue,
        } => {
            if let Some(item) = removed_item {
                scrub_queue_item(item, redact);
            }
            scrub_queue(queue, redact);
        }
        proto::Response::RemoveQueuedUserMessagesResult {
            applied: _,
            reason: _,
            removed_items,
            queue,
        } => {
            scrub_queue(removed_items, redact);
            scrub_queue(queue, redact);
        }
        proto::Response::Attached {
            session_id: _,
            short_id: _,
            project_root,
            project_id: _,
            active_agent: _,
            active_agent_path: _,
            foreground_target: _,
            active_subagent,
            active_model_state: _,
            history,
            paused_work,
            repair_required,
            daemon_version: _,
            compatible: _,
            env_baseline: _,
            env_session: _,
            env_drift,
            env_policy_applied: _,
            btw_fork: _,
        } => {
            scrub_string(project_root, redact);
            if let Some(active) = active_subagent {
                scrub_active_subagent(active, redact);
            }
            scrub_history_entries(history, redact);
            scrub_paused_work(paused_work, redact);
            if let Some(repair) = repair_required {
                scrub_resume_repair_state(repair, redact);
            }
            if let Some(drift) = env_drift {
                scrub_env_diff_summary(drift, redact);
            }
        }
        proto::Response::SubagentTranscript {
            session_id: _,
            task_call_id: _,
            label,
            history,
        } => {
            scrub_string(label, redact);
            scrub_history_entries(history, redact);
        }
        proto::Response::Sessions { sessions } => {
            for session in sessions {
                scrub_session_summary(session, redact);
            }
        }
        proto::Response::SessionMessages {
            session_id: _,
            messages,
            has_more: _,
        } => {
            for message in messages {
                scrub_session_message(message, redact);
            }
        }
        proto::Response::GoalStatus { goal } => {
            if let Some(goal) = goal {
                scrub_goal_summary(goal, redact);
            }
        }
        proto::Response::GoalUpdated { goal } => scrub_goal_summary(goal, redact),
        proto::Response::GoalCleared { cleared: _ } => {}
        proto::Response::Assistants { assistants } => {
            for assistant in assistants {
                scrub_assistant_summary(assistant, redact);
            }
        }
        proto::Response::AssistantSessionCreated { session } => {
            scrub_assistant_session_created(session, redact);
        }
        proto::Response::AutoTitle {
            session_id: _,
            title,
        } => scrub_string(title, redact),
        proto::Response::ExportSessionData { data } => scrub_export_session_data(data, redact),
        proto::Response::Curator { result } => scrub_curator_result(result, redact),
        proto::Response::Forked {
            session_id: _,
            short_id: _,
            parent_session_id: _,
            fork_point_turn_id: _,
        } => {}
        proto::Response::BtwFork {
            info: _,
            created: _,
        } => {}
        proto::Response::Skills { skills } => {
            for skill in skills {
                scrub_skill_summary(skill, redact);
            }
        }
        proto::Response::ResourceSnapshot { snapshot } => {
            scrub_resource_scheduler_snapshot(snapshot, redact);
        }
        proto::Response::PromoteResourceResult {
            status: _,
            message,
            snapshot,
        } => {
            scrub_string(message, redact);
            scrub_resource_scheduler_snapshot(snapshot, redact);
        }
        proto::Response::ScheduledJob { job } => scrub_scheduled_job_summary(job, redact),
        proto::Response::ScheduledJobs { jobs } => {
            for job in jobs {
                scrub_scheduled_job_summary(job, redact);
            }
        }
        proto::Response::ScheduledJobDeleted { id: _, deleted: _ } => {}
        proto::Response::ScheduledJobRunQueued { id: _ } => {}
        proto::Response::Agents { agents } => {
            for agent in agents {
                scrub_agent_summary(agent, redact);
            }
        }
        proto::Response::Models { models } => {
            for model in models {
                scrub_model_summary(model, redact);
            }
        }
        proto::Response::FsList {
            entries,
            truncated: _,
        } => {
            for entry in entries {
                scrub_fs_entry(entry, redact);
            }
        }
        proto::Response::FsStat { entry } => scrub_fs_entry(entry, redact),
        proto::Response::FsRead {
            content,
            hash: _,
            truncated: _,
            kind: _,
        } => scrub_option_string(content, redact),
        proto::Response::GitStatus { entries } => {
            for entry in entries {
                scrub_string(&mut entry.raw, redact);
            }
        }
        proto::Response::GitDiffFile { diff, truncated: _ } => scrub_string(diff, redact),
        proto::Response::LspControlResult { message } => scrub_string(message, redact),
        proto::Response::DaemonStatus {
            pid: _,
            uptime_secs: _,
            active_sessions: _,
            socket_path,
            daemon_version: _,
            protocol_version: _,
            paused_sessions: _,
            database_path,
            schema_version: _,
        } => {
            scrub_string(socket_path, redact);
            scrub_string(database_path, redact);
        }
        proto::Response::GuidanceEstimate {
            file,
            tokens: _,
            system_tokens: _,
            model_instruction_tokens: _,
        } => scrub_option_string(file, redact),
        proto::Response::StatsRollup { rollup } => scrub_stats_rollup(rollup, redact),
        proto::Response::CaffeinateState {
            active: _,
            lid_close_guaranteed: _,
            message,
        } => scrub_string(message, redact),
        proto::Response::PausedWork { items } => scrub_paused_work(items, redact),
    }
}

fn scrub_event_free_text(event: &mut proto::Event, redact: &RedactionTable) {
    match event {
        proto::Event::EnvDriftWarning {
            baseline: _,
            candidate: _,
            diff,
            policy: _,
        } => scrub_env_diff_summary(diff, redact),
        proto::Event::ConfigSnapshot { snapshot: _ } => {}
        proto::Event::QueueUpdated {
            session_id: _,
            queue,
        } => scrub_queue(queue, redact),
        proto::Event::ForegroundInputTarget {
            session_id: _,
            target: _,
        }
        | proto::Event::ActiveModelState {
            session_id: _,
            provider: _,
            model: _,
            config_provider: _,
            config_model: _,
            diverged: _,
            generation: _,
        }
        | proto::Event::PreflightStarted { session_id: _ }
        | proto::Event::UserMessageRetracted { session_id: _ }
        | proto::Event::Usage {
            session_id: _,
            agent: _,
            input_tokens: _,
            output_tokens: _,
            cached_input_tokens: _,
            cache_creation_input_tokens: _,
        }
        | proto::Event::InterruptQueueChanged {
            session_id: _,
            active_interrupt_id: _,
            pending_count: _,
        }
        | proto::Event::InterruptResolved {
            session_id: _,
            interrupt_id: _,
            decision: _,
            seq: _,
        }
        | proto::Event::AgentIdle {
            session_id: _,
            turn_id: _,
            reason: _,
        }
        | proto::Event::LlmModeChanged {
            session_id: _,
            mode: _,
        }
        | proto::Event::ContextProjection {
            session_id: _,
            prunable_tokens: _,
            cache_cold: _,
        }
        | proto::Event::SandboxState {
            session_id: _,
            mode: _,
            enabled: _,
            container_network_enabled: _,
            container_availability: _,
        }
        | proto::Event::SandboxEscalationState {
            session_id: _,
            enabled: _,
        }
        | proto::Event::RedactionState {
            session_id: _,
            scan_environment: _,
            scan_dotenv: _,
            scan_ssh_keys: _,
        }
        | proto::Event::TrustedOnlyState {
            session_id: _,
            enabled: _,
        }
        | proto::Event::ApprovalModeState {
            session_id: _,
            mode: _,
        }
        | proto::Event::DelegationRecursionState {
            session_id: _,
            enabled: _,
            default_depth: _,
        }
        | proto::Event::GitignoreAllow {
            session_id: _,
            allow: _,
        }
        | proto::Event::TerminalOutput {
            terminal_id: _,
            bytes: _,
        }
        | proto::Event::TerminalViewers {
            terminal_id: _,
            count: _,
        }
        | proto::Event::DaemonDraining { forced: _ } => {}
        proto::Event::ThinkingStarted {
            session_id: _,
            agent: _,
            turn_id: _,
        } => {}
        proto::Event::Reconnecting {
            session_id: _,
            agent: _,
            attempt: _,
            provider: _,
            model: _,
            url,
        } => scrub_string(url, redact),
        proto::Event::InferenceWarning {
            session_id: _,
            agent: _,
            provider: _,
            model: _,
            phase: _,
            waited_secs: _,
        } => {}
        proto::Event::AssistantTextDelta {
            session_id: _,
            agent: _,
            delta,
        }
        | proto::Event::ReasoningDelta {
            session_id: _,
            agent: _,
            delta,
        } => scrub_string(delta, redact),
        proto::Event::AssistantText {
            session_id: _,
            agent: _,
            text,
            reasoning,
            seq: _,
        } => {
            scrub_string(text, redact);
            scrub_string(reasoning, redact);
        }
        proto::Event::UserMessageRecorded {
            session_id: _,
            seq: _,
            preflight_cleaned,
        } => scrub_option_string(preflight_cleaned, redact),
        proto::Event::QueuedUserMessagesFolded {
            session_id: _,
            text,
            display_text,
            tag_expansions,
            queue_item_ids: _,
            target: _,
            seq: _,
            preflight_cleaned,
        } => {
            scrub_string(text, redact);
            scrub_option_string(display_text, redact);
            scrub_tag_expansions(tag_expansions, redact);
            scrub_option_string(preflight_cleaned, redact);
        }
        proto::Event::SessionPersistFailed {
            session_id: _,
            error,
        }
        | proto::Event::SessionDriverFailed {
            session_id: _,
            turn_id: _,
            error,
        } => scrub_string(error, redact),
        proto::Event::Notice {
            session_id: _,
            text,
        }
        | proto::Event::LspNotice { text }
        | proto::Event::ScheduleNote {
            session_id: _,
            job_id: _,
            text,
        }
        | proto::Event::TerminalClipboard {
            terminal_id: _,
            text,
        } => scrub_string(text, redact),
        proto::Event::SkillAutoInjected {
            session_id: _,
            name: _,
            reason,
        } => scrub_option_string(reason, redact),
        proto::Event::ToolStart {
            session_id: _,
            agent: _,
            call_id: _,
            tool: _,
            args,
        } => scrub_json_strings(args, redact),
        proto::Event::ToolEnd {
            session_id: _,
            agent: _,
            call_id: _,
            tool: _,
            output,
            truncated: _,
            seq: _,
            hint,
        } => {
            scrub_string(output, redact);
            scrub_option_string(hint, redact);
        }
        proto::Event::ResourceWait {
            session_id: _,
            agent: _,
            request_id: _,
            display_id: _,
            resources: _,
            queue_position: _,
            command_label,
        }
        | proto::Event::ResourceStart {
            session_id: _,
            agent: _,
            request_id: _,
            display_id: _,
            resources: _,
            wait_ms: _,
            command_label,
        }
        | proto::Event::ResourceClear {
            session_id: _,
            agent: _,
            request_id: _,
            display_id: _,
            resources: _,
            command_label,
        } => scrub_option_string(command_label, redact),
        proto::Event::ToolError {
            session_id: _,
            agent: _,
            call_id: _,
            tool: _,
            error,
            kind: _,
            seq: _,
        } => scrub_string(error, redact),
        proto::Event::InferenceFailed {
            session_id: _,
            agent: _,
            provider: _,
            model: _,
            error_class: _,
            detail,
            auth_failure,
        } => {
            scrub_string(detail, redact);
            if let Some(auth) = auth_failure {
                scrub_auth_failure(auth, redact);
            }
        }
        proto::Event::InferenceSucceeded {
            session_id: _,
            provider: _,
            model: _,
        } => {}
        proto::Event::BackupUsed {
            session_id: _,
            agent: _,
            primary_model: _,
            error_class: _,
            backup_model: _,
        } => {}
        proto::Event::SubagentSpawned {
            session_id: _,
            parent: _,
            child: _,
            task_call_id: _,
            label,
            prompt,
            requested_cwd,
            resolved_cwd,
            trusted_only: _,
            model_trusted: _,
            routing,
        } => {
            scrub_string(label, redact);
            scrub_string(prompt, redact);
            scrub_option_string(requested_cwd, redact);
            scrub_option_string(resolved_cwd, redact);
            scrub_json_strings(routing, redact);
        }
        proto::Event::SubagentRouting {
            session_id: _,
            task_call_id: _,
            label,
            child: _,
            provider,
            model,
            trusted_only: _,
            model_trusted: _,
            routing,
        } => {
            scrub_string(label, redact);
            scrub_string(provider, redact);
            scrub_string(model, redact);
            scrub_json_strings(routing, redact);
        }
        proto::Event::SubagentReport {
            session_id: _,
            agent: _,
            task_call_id: _,
            label,
            report,
            failed: _,
            trusted_only: _,
            model_trusted: _,
            routing,
        } => {
            scrub_string(label, redact);
            scrub_string(report, redact);
            scrub_json_strings(routing, redact);
        }
        proto::Event::NestedTurn {
            session_id: _,
            task_call_id: _,
            label,
            parent_task_call_id: _,
            inner,
        } => {
            scrub_string(label, redact);
            scrub_event_free_text(inner, redact);
        }
        proto::Event::InterruptRaised {
            session_id: _,
            interrupt_id: _,
            agent: _,
            description,
            question,
            questions,
            pending_count: _,
            reason: _,
        } => {
            scrub_string(description, redact);
            if let Some(question) = question {
                scrub_interrupt_question(question, redact);
            }
            if let Some(questions) = questions {
                scrub_interrupt_question_set(questions, redact);
            }
        }
        proto::Event::HistoryReplay {
            session_id: _,
            entries,
            max_seq: _,
        } => scrub_history_entries(entries, redact),
        proto::Event::PrimarySwapped {
            session_id: _,
            name: _,
        } => {}
        proto::Event::SessionEnded {
            session_id: _,
            reason,
        } => scrub_string(reason, redact),
        proto::Event::ScheduleStarted {
            session_id: _,
            job_id: _,
            label,
            kind: _,
        }
        | proto::Event::ScheduleCompleted {
            session_id: _,
            job_id: _,
            label,
            kind: _,
            failed: _,
        } => scrub_string(label, redact),
        proto::Event::ScheduleProgress {
            session_id: _,
            job_id: _,
        } => {}
        proto::Event::Pruned {
            session_id: _,
            auto: _,
            bodies: _,
            tokens_saved: _,
            elided: _,
            trigger_reason: _,
            cache_break: _,
        } => {}
        proto::Event::CompactReady {
            session_id: _,
            new_session_id: _,
            handoff,
            brief,
            source: _,
            trigger_ctx_pct: _,
            tokens_before: _,
            tokens_after: _,
            turns_summarized: _,
            tail_kept: _,
            tail_trimmed: _,
            seed_tool_count: _,
            seed_tool_tokens: _,
        } => {
            scrub_string(handoff, redact);
            scrub_string(brief, redact);
        }
        proto::Event::SandboxUnavailable {
            session_id: _,
            remedy,
            fix_command,
        } => {
            scrub_string(remedy, redact);
            scrub_option_string(fix_command, redact);
        }
        proto::Event::CommandCapabilityUnavailable {
            session_id: _,
            text,
            fix_command,
        } => {
            scrub_string(text, redact);
            scrub_option_string(fix_command, redact);
        }
        proto::Event::PreflightState {
            session_id: _,
            enabled: _,
        } => {}
        proto::Event::TandemState {
            session_id: _,
            models: _,
            warning,
        } => scrub_option_string(warning, redact),
        proto::Event::CaffeinateState {
            active: _,
            lid_close_guaranteed: _,
            message,
        } => scrub_option_string(message, redact),
        proto::Event::ConnectorStatus {
            enabled: _,
            status: _,
            relay_url: _,
            relay_id: _,
            relay_region: _,
            last_error,
        } => scrub_option_string(last_error, redact),
        proto::Event::TerminalClosed {
            terminal_id: _,
            reason,
            exit_code: _,
        } => scrub_string(reason, redact),
        proto::Event::PausedWorkAvailable {
            session_id: _,
            items,
        } => scrub_paused_work(items, redact),
        proto::Event::WaitingForLock {
            session_id: _,
            path,
            holder_agent: _,
            waiting: _,
        } => scrub_string(path, redact),
    }
}

fn scrub_history_entries(entries: &mut [proto::HistoryEntry], redact: &RedactionTable) {
    for entry in entries {
        scrub_history_entry_free_text(entry, redact);
    }
}

fn scrub_history_entry_free_text(entry: &mut proto::HistoryEntry, redact: &RedactionTable) {
    match entry {
        proto::HistoryEntry::InterruptDecision { decision, seq: _ } => {
            scrub_interrupt_decision(decision, redact);
        }
        proto::HistoryEntry::User {
            text,
            display_text,
            tag_expansions,
            ts_ms: _,
            seq: _,
            origin_principal: _,
        } => {
            scrub_string(text, redact);
            scrub_option_string(display_text, redact);
            scrub_tag_expansions(tag_expansions, redact);
        }
        proto::HistoryEntry::Assistant {
            agent: _,
            text,
            reasoning,
            ts_ms: _,
            seq: _,
        } => {
            scrub_string(text, redact);
            scrub_string(reasoning, redact);
        }
        proto::HistoryEntry::ToolCall {
            seq: _,
            agent: _,
            call_id: _,
            parent_call_id: _,
            parent_child_index: _,
            tool: _,
            mcp_server: _,
            mcp_builtin: _,
            mcp_kind: _,
            original_input,
            wire_input,
            recovery_kind: _,
            recovery_stage: _,
            output,
            hard_fail: _,
            truncated: _,
            hint,
        } => {
            scrub_json_strings(original_input, redact);
            scrub_json_strings(wire_input, redact);
            scrub_string(output, redact);
            scrub_option_string(hint, redact);
        }
        proto::HistoryEntry::InferenceError {
            seq: _,
            summary,
            detail,
        } => {
            scrub_string(summary, redact);
            scrub_string(detail, redact);
        }
        proto::HistoryEntry::CompactBoundary {
            seq: _,
            predecessor_short_id: _,
            seed_tool_count: _,
            seed_tool_tokens: _,
            source: _,
            trigger_ctx_pct: _,
            tokens_before: _,
            tokens_after: _,
            turns_summarized: _,
            tail_kept: _,
            tail_trimmed: _,
            brief,
            handoff,
        } => {
            scrub_option_string(brief, redact);
            scrub_option_string(handoff, redact);
        }
        proto::HistoryEntry::Subagent {
            seq: _,
            parent: _,
            child: _,
            task_call_id: _,
            label,
        } => scrub_string(label, redact),
    }
}

fn scrub_queue(queue: &mut [proto::QueueItem], redact: &RedactionTable) {
    for item in queue {
        scrub_queue_item(item, redact);
    }
}

fn scrub_queue_item(item: &mut proto::QueueItem, redact: &RedactionTable) {
    let proto::QueueItem {
        id: _,
        status: _,
        text,
        display_text,
        target: _,
    } = item;
    scrub_string(text, redact);
    scrub_option_string(display_text, redact);
}

fn scrub_tag_expansions(items: &mut [proto::TagExpansionMeta], redact: &RedactionTable) {
    for item in items {
        let proto::TagExpansionMeta {
            tool,
            path,
            detail,
            ok: _,
        } = item;
        scrub_string(tool, redact);
        scrub_string(path, redact);
        scrub_string(detail, redact);
    }
}

fn scrub_delegation_steer_result(
    result: &mut proto::DelegationSteerResult,
    redact: &RedactionTable,
) {
    let proto::DelegationSteerResult {
        status: _,
        task_call_id: _,
        label,
        message,
        pending_steers: _,
        origin_principal: _,
        scrubbed: _,
    } = result;
    scrub_option_string(label, redact);
    scrub_string(message, redact);
}

fn scrub_active_subagent(active: &mut proto::ActiveSubagent, redact: &RedactionTable) {
    let proto::ActiveSubagent {
        parent: _,
        child: _,
        task_call_id: _,
        label,
    } = active;
    scrub_string(label, redact);
}

fn scrub_paused_work(items: &mut [proto::PausedWorkSummary], redact: &RedactionTable) {
    for item in items {
        let proto::PausedWorkSummary {
            session_id: _,
            active_agent: _,
            project_root,
            reason,
            pending_tool_count: _,
            daemon_version: _,
            client_version: _,
            updated_at: _,
        } = item;
        scrub_string(project_root, redact);
        scrub_string(reason, redact);
    }
}

fn scrub_resume_repair_state(state: &mut proto::ResumeRepairState, redact: &RedactionTable) {
    let proto::ResumeRepairState {
        session_id: _,
        short_id: _,
        provider: _,
        model: _,
        wire_api: _,
        failure_kind: _,
        failing_tool_call_ids: _,
        safe_last_turn_seq: _,
        suggested_actions: _,
        detail,
    } = state;
    scrub_string(detail, redact);
}

fn scrub_session_summary(summary: &mut proto::SessionSummary, redact: &RedactionTable) {
    let proto::SessionSummary {
        session_id: _,
        short_id: _,
        project_root,
        project_id: _,
        started_at: _,
        last_active_at: _,
        turns: _,
        active_agent: _,
        title,
        parent_session_id: _,
        created_by_principal: _,
        shared_with_collaborators: _,
        fork_count: _,
        descendant_count: _,
        last_viewed_at: _,
        latest_activity_at: _,
        open_interrupts: _,
        activity_state: _,
        archived_at: _,
        pin_count: _,
    } = summary;
    scrub_string(project_root, redact);
    scrub_option_string(title, redact);
}

fn scrub_goal_summary(goal: &mut proto::GoalSummary, redact: &RedactionTable) {
    let proto::GoalSummary {
        id: _,
        session_id: _,
        project_id,
        objective,
        context,
        status: _,
        token_budget: _,
        tokens_used: _,
        blocked_attempts: _,
        last_read_at: _,
        created_at: _,
        updated_at: _,
    } = goal;
    scrub_string(project_id, redact);
    scrub_string(objective, redact);
    scrub_option_string(context, redact);
}

fn scrub_assistant_summary(assistant: &mut proto::AssistantSummary, redact: &RedactionTable) {
    let proto::AssistantSummary {
        name,
        created_at: _,
        home_dir,
        config_json,
        content_hash,
    } = assistant;
    scrub_string(name, redact);
    scrub_string(home_dir, redact);
    scrub_string(config_json, redact);
    scrub_string(content_hash, redact);
}

fn scrub_assistant_session_created(
    session: &mut proto::AssistantSessionCreated,
    redact: &RedactionTable,
) {
    let proto::AssistantSessionCreated {
        session_id: _,
        short_id: _,
        project_root,
        project_id,
        assistant_name,
        active_agent,
    } = session;
    scrub_string(project_root, redact);
    scrub_string(project_id, redact);
    scrub_string(assistant_name, redact);
    scrub_string(active_agent, redact);
}

fn scrub_export_session_data(data: &mut proto::ExportSessionData, redact: &RedactionTable) {
    scrub_string(&mut data.filename_extension, redact);
    scrub_string(&mut data.mime, redact);
}

fn scrub_curator_result(result: &mut proto::CuratorResult, redact: &RedactionTable) {
    match result {
        proto::CuratorResult::Status { status } => scrub_curator_status(status, redact),
        proto::CuratorResult::Run { report } => scrub_curator_run_report(report, redact),
        proto::CuratorResult::Pinned { name, pinned: _ }
        | proto::CuratorResult::Restored { name } => scrub_string(name, redact),
        proto::CuratorResult::Snapshots { snapshots } => {
            for snapshot in snapshots {
                scrub_curator_snapshot(snapshot, redact);
            }
        }
        proto::CuratorResult::RolledBack { snapshot } => scrub_curator_snapshot(snapshot, redact),
    }
}

fn scrub_curator_status(status: &mut proto::CuratorStatus, redact: &RedactionTable) {
    for skill in &mut status.skills {
        scrub_string(&mut skill.name, redact);
        scrub_string(&mut skill.state, redact);
        scrub_string(&mut skill.created_by, redact);
        scrub_string(&mut skill.source_path, redact);
        scrub_option_string(&mut skill.archive_path, redact);
    }
    for snapshot in &mut status.snapshots {
        scrub_curator_snapshot(snapshot, redact);
    }
}

fn scrub_curator_snapshot(snapshot: &mut proto::CuratorSnapshotStatus, redact: &RedactionTable) {
    scrub_string(&mut snapshot.id, redact);
    scrub_string(&mut snapshot.path, redact);
    scrub_string(&mut snapshot.reason, redact);
}

fn scrub_curator_run_report(report: &mut proto::CuratorRunReport, redact: &RedactionTable) {
    scrub_strings(&mut report.stale, redact);
    scrub_strings(&mut report.archived, redact);
    scrub_strings(&mut report.reactivated, redact);
    scrub_strings(&mut report.skipped, redact);
    scrub_option_string(&mut report.snapshot_id, redact);
    scrub_option_string(&mut report.consolidation, redact);
}

fn scrub_stats_rollup(rollup: &mut proto::StatsRollup, redact: &RedactionTable) {
    scrub_option_string(&mut rollup.project_id, redact);
    for row in &mut rollup.tokens.by_model {
        scrub_string(&mut row.model, redact);
        scrub_string(&mut row.provider, redact);
    }
    if let Some(rows) = &mut rollup.tokens.by_role {
        for row in rows {
            scrub_string(&mut row.model, redact);
            scrub_string(&mut row.provider, redact);
            scrub_string(&mut row.agent, redact);
        }
    }
    for row in &mut rollup.recovery.by_model {
        scrub_string(&mut row.model, redact);
    }
    for row in &mut rollup.recovery.by_tool {
        scrub_string(&mut row.model, redact);
        scrub_string(&mut row.tool, redact);
    }
    for row in &mut rollup.recovery.by_stage {
        scrub_string(&mut row.model, redact);
        scrub_string(&mut row.recovery_kind, redact);
        scrub_string(&mut row.recovery_stage, redact);
    }
    for row in &mut rollup.language.languages {
        scrub_string(&mut row.language, redact);
    }
    for row in &mut rollup.language.non_file {
        scrub_string(&mut row.tool, redact);
    }
}

fn scrub_session_message(message: &mut proto::SessionMessage, redact: &RedactionTable) {
    let proto::SessionMessage {
        seq: _,
        ts_ms: _,
        role: _,
        text,
    } = message;
    scrub_string(text, redact);
}

fn scrub_skill_summary(skill: &mut proto::SkillSummary, redact: &RedactionTable) {
    let proto::SkillSummary {
        name: _,
        description,
        source,
        user_invocable: _,
    } = skill;
    scrub_string(description, redact);
    scrub_string(source, redact);
}

fn scrub_agent_summary(agent: &mut proto::AgentSummary, redact: &RedactionTable) {
    let proto::AgentSummary {
        name: _,
        description,
        mode: _,
        source,
        builtin: _,
    } = agent;
    scrub_string(description, redact);
    scrub_string(source, redact);
}

fn scrub_model_summary(model: &mut proto::ModelSummary, redact: &RedactionTable) {
    let proto::ModelSummary {
        provider: _,
        id: _,
        display_name,
        favorite: _,
    } = model;
    scrub_option_string(display_name, redact);
}

fn scrub_scheduled_job_summary(job: &mut proto::ScheduledJobSummary, redact: &RedactionTable) {
    let proto::ScheduledJobSummary {
        id: _,
        owner: _,
        schedule: _,
        payload,
        enabled: _,
        missed_run_policy: _,
        last_run_at: _,
        next_run_at: _,
        last_result,
        failure_count: _,
        backoff_until: _,
        disabled_notice,
    } = job;
    match payload {
        proto::ScheduledJobPayload::RunPrompt {
            assistant: _,
            prompt,
            project_root,
        } => {
            scrub_string(prompt, redact);
            scrub_string(project_root, redact);
        }
        proto::ScheduledJobPayload::Callback { subsystem: _ } => {}
    }
    if let Some(result) = last_result {
        scrub_scheduled_job_last_result(result, redact);
    }
    scrub_option_string(disabled_notice, redact);
}

fn scrub_scheduled_job_last_result(
    result: &mut proto::ScheduledJobLastResult,
    redact: &RedactionTable,
) {
    scrub_string(&mut result.summary, redact);
}

fn scrub_fs_entry(entry: &mut proto::FsEntry, redact: &RedactionTable) {
    let proto::FsEntry {
        name,
        path,
        kind: _,
        size: _,
        mtime_ms: _,
        gitignored: _,
        blocked: _,
        symlink_target,
    } = entry;
    scrub_string(name, redact);
    scrub_string(path, redact);
    scrub_option_string(symlink_target, redact);
}

fn scrub_resource_scheduler_snapshot(
    snapshot: &mut proto::ResourceSchedulerSnapshot,
    redact: &RedactionTable,
) {
    let proto::ResourceSchedulerSnapshot {
        enabled: _,
        pools,
        running,
        queued,
        max_queued: _,
    } = snapshot;
    for pool in pools {
        let proto::ResourcePoolSnapshot {
            name: _,
            capacity: _,
            used: _,
            available: _,
        } = pool;
    }
    for item in running {
        let proto::ResourceRunningSnapshot {
            id: _,
            display_id: _,
            resources,
            metadata,
            queued_at_ms: _,
            started_at_ms: _,
            wait_ms: _,
            promoted_by: _,
            promoted_at_ms: _,
        } = item;
        scrub_resource_requirements(resources, redact);
        scrub_resource_request_metadata(metadata, redact);
    }
    for item in queued {
        let proto::ResourceQueuedSnapshot {
            id: _,
            display_id: _,
            resources,
            metadata,
            queued_at_ms: _,
            wait_ms: _,
            promoted_by: _,
            promoted_at_ms: _,
            state: _,
        } = item;
        scrub_resource_requirements(resources, redact);
        scrub_resource_request_metadata(metadata, redact);
    }
}

fn scrub_resource_requirements(
    requirements: &mut proto::ResourceRequirements,
    _redact: &RedactionTable,
) {
    let proto::ResourceRequirements { pools: _ } = requirements;
}

fn scrub_resource_request_metadata(
    metadata: &mut proto::ResourceRequestMetadata,
    redact: &RedactionTable,
) {
    let proto::ResourceRequestMetadata {
        session_id: _,
        agent_id: _,
        tool_call_id: _,
        command_label,
        declared_requirements,
        policy_requirements,
        reviewer_requirements,
        effective_requirements,
    } = metadata;
    scrub_option_string(command_label, redact);
    scrub_resource_requirements(declared_requirements, redact);
    scrub_resource_requirements(policy_requirements, redact);
    scrub_resource_requirements(reviewer_requirements, redact);
    scrub_resource_requirements(effective_requirements, redact);
}

fn scrub_env_diff_summary(diff: &mut EnvDiffSummary, redact: &RedactionTable) {
    let EnvDiffSummary {
        baseline_digest: _,
        candidate_digest: _,
        added_keys: _,
        removed_keys: _,
        changed_keys: _,
        changed_secret_keys,
        path_added,
        path_removed,
    } = diff;
    scrub_strings(changed_secret_keys, redact);
    scrub_strings(path_added, redact);
    scrub_strings(path_removed, redact);
}

fn scrub_auth_failure(auth: &mut proto::AuthFailureKind, _redact: &RedactionTable) {
    match auth {
        proto::AuthFailureKind::CredentialsRejected { status: _ }
        | proto::AuthFailureKind::MissingEntitlement { feature: _ }
        | proto::AuthFailureKind::OAuthExpired { provider: _ }
        | proto::AuthFailureKind::ProviderNotConfigured => {}
    }
}

fn scrub_interrupt_question_set(set: &mut proto::InterruptQuestionSet, redact: &RedactionTable) {
    let proto::InterruptQuestionSet { questions } = set;
    for question in questions {
        scrub_interrupt_question(question, redact);
    }
}

fn scrub_interrupt_question(question: &mut proto::InterruptQuestion, redact: &RedactionTable) {
    match question {
        proto::InterruptQuestion::Single {
            prompt,
            options,
            allow_freetext: _,
            command_detail,
            permission: _,
            approval_class: _,
            sandbox_escalation,
        } => {
            scrub_string(prompt, redact);
            scrub_interrupt_options(options, redact);
            if let Some(detail) = command_detail {
                scrub_command_detail(detail, redact);
            }
            if let Some(escalation) = sandbox_escalation {
                scrub_sandbox_escalation(escalation, redact);
            }
        }
        proto::InterruptQuestion::Multi {
            prompt,
            options,
            allow_freetext: _,
        } => {
            scrub_string(prompt, redact);
            scrub_interrupt_options(options, redact);
        }
        proto::InterruptQuestion::Freetext { prompt, masked: _ } => scrub_string(prompt, redact),
    }
}

fn scrub_interrupt_options(options: &mut [proto::InterruptOption], redact: &RedactionTable) {
    for option in options {
        let proto::InterruptOption {
            id: _,
            label,
            description,
            secondary: _,
        } = option;
        scrub_string(label, redact);
        scrub_option_string(description, redact);
    }
}

fn scrub_command_detail(detail: &mut proto::CommandDetail, redact: &RedactionTable) {
    let proto::CommandDetail {
        full_command,
        highlight: _,
        step: _,
        step_count: _,
        cwd,
        remembered_key,
        write_content,
        risk_tier,
        risk_reasons,
        affected_targets,
        native_tool_hints,
        offered_scopes,
        policy_cap,
    } = detail;
    scrub_string(full_command, redact);
    scrub_option_string(cwd, redact);
    scrub_option_string(remembered_key, redact);
    if let Some(write_content) = write_content {
        scrub_write_content_preview(write_content, redact);
    }
    scrub_option_string(risk_tier, redact);
    scrub_strings(risk_reasons, redact);
    scrub_strings(affected_targets, redact);
    scrub_strings(native_tool_hints, redact);
    scrub_strings(offered_scopes, redact);
    scrub_option_string(policy_cap, redact);
}

fn scrub_write_content_preview(preview: &mut proto::WriteContentPreview, redact: &RedactionTable) {
    let proto::WriteContentPreview {
        content,
        dynamic: _,
    } = preview;
    scrub_string(content, redact);
}

fn scrub_sandbox_escalation(escalation: &mut proto::SandboxEscalation, redact: &RedactionTable) {
    let proto::SandboxEscalation {
        confined_exit: _,
        confined_stderr,
        suggested_paths,
        suggested_access,
    } = escalation;
    scrub_string(confined_stderr, redact);
    scrub_strings(suggested_paths, redact);
    scrub_option_string(suggested_access, redact);
}

fn scrub_interrupt_decision(decision: &mut proto::InterruptDecision, redact: &RedactionTable) {
    let proto::InterruptDecision {
        permission: _,
        cancelled: _,
        lines,
    } = decision;
    for line in lines {
        let proto::InterruptDecisionLine { prompt, answer } = line;
        scrub_string(prompt, redact);
        scrub_string(answer, redact);
    }
}

fn scrub_string(value: &mut String, redact: &RedactionTable) {
    *value = redact.scrub(value);
}

fn scrub_option_string(value: &mut Option<String>, redact: &RedactionTable) {
    if let Some(value) = value {
        scrub_string(value, redact);
    }
}

fn scrub_strings(values: &mut [String], redact: &RedactionTable) {
    for value in values {
        scrub_string(value, redact);
    }
}

/// Daemon-wide singletons. Held in an `Arc` so per-client tasks can
/// share without copying.
pub struct DaemonContext {
    pub db: Db,
    pub registry: SessionRegistry,
    pub paths: DaemonPaths,
    pub started_at: Instant,
    /// Caffeination authority (`/caffeinate`, GOALS §1a chrome glyph).
    /// Holds the OS sleep assertion **in the daemon process** so it
    /// survives TUI-client exit, plus the on/off + until-idle state.
    pub caffeinate: Arc<crate::daemon::caffeinate::CaffeineController>,
    /// Daemon-global event bus. Unlike the per-session broadcast on each
    /// worker, every client task subscribes to this regardless of which
    /// (if any) session it's attached to — so a daemon-global event like
    /// [`proto::Event::CaffeinateState`] reaches *all* connected clients.
    global_events: EventSender,
    global_redaction: SharedRedactionTable,
    pub terminal_host: crate::daemon::terminal::TerminalHostHandle,
    /// Live count of connected clients. Each [`handle_client`] task
    /// increments on accept and decrements on exit. The ephemeral
    /// self-reaping watchdog (Layer C) watches the receiver side for
    /// "no clients" transitions; the persistent daemon ignores it.
    client_count: tokio::sync::watch::Sender<usize>,
    /// Daemon-wide graceful-shutdown gate
    /// (`daemon-graceful-drain-shutdown.md`). Shared with the registry
    /// (installed into worker models). New `SendUserMessage` requests are
    /// refused while it reports draining.
    shutdown: crate::daemon::shutdown::ShutdownSignal,
    shutdown_grace_override: StdMutex<Option<Duration>>,
    env_baseline: Arc<std::sync::RwLock<EnvSnapshot>>,
    upload_accounting: Arc<StdMutex<UploadAccounting>>,
    connector_wake: watch::Sender<u64>,
    pub scheduler: Option<DaemonSchedulerHandle>,
    credential_store_path: Option<PathBuf>,
    /// Injectable config-resolution seam (`daemon-trust-test-isolation.md`):
    /// the single route by which request handling resolves layered
    /// provider/extended config. Shared with the registry so attach-create,
    /// resume, and worker startup all consult the same source.
    config_source: crate::daemon::config_source::ConfigSource,
}

impl DaemonContext {
    fn caffeinate_state_event(&self) -> proto::Event {
        let snap = self.caffeinate.snapshot();
        proto::Event::CaffeinateState {
            active: snap.active,
            lid_close_guaranteed: false,
            message: None,
        }
    }

    fn drain_state_event(&self) -> Option<proto::Event> {
        match self.shutdown.phase() {
            ShutdownPhase::Running => None,
            ShutdownPhase::Draining | ShutdownPhase::Forced => Some(proto::Event::DaemonDraining {
                forced: self.shutdown.is_forced(),
            }),
        }
    }

    pub fn new(
        db: Db,
        locks: Arc<LockManager>,
        paths: DaemonPaths,
        terminal_factory: crate::daemon::terminal::TerminalHostFactory,
        config_source: crate::daemon::config_source::ConfigSource,
    ) -> Self {
        // The daemon-wide graceful-shutdown gate
        // (`daemon-graceful-drain-shutdown.md`) — the central drain
        // authority. Built here and shared into the registry (which installs
        // it into every worker's model) so the inference-dispatch chokepoint,
        // the new-user-work gate, and teardown all read one state.
        let shutdown = crate::daemon::shutdown::ShutdownSignal::new();
        let resource_scheduler = (!paths.ephemeral).then(|| {
            Arc::new(crate::engine::resource_scheduler::ResourceScheduler::new(
                ExtendedConfig::default().resource_scheduler,
            ))
        });
        let registry = SessionRegistry::new(
            db.clone(),
            locks,
            shutdown.clone(),
            resource_scheduler,
            config_source.clone(),
        );
        let (client_count, _) = tokio::sync::watch::channel(0usize);
        let (connector_wake, _) = watch::channel(0u64);
        let (global_events, _) = broadcast::channel(GLOBAL_EVENT_CAPACITY);
        let global_redaction = Arc::new(std::sync::RwLock::new(build_daemon_redaction_table()));
        let terminal_host = terminal_factory.build(
            global_events.clone(),
            global_redaction.clone(),
            terminal_temp_root(&paths),
        );
        let container = Arc::new(crate::container::ContainerManager::detect());
        let _ = crate::container::container_manager().set((*container).clone());
        spawn_terminal_reaper(terminal_host.clone(), shutdown.clone());
        registry
            .lsp_manager()
            .set_notice_bus(global_events.clone(), global_redaction.clone());
        registry.set_global_bus(global_events.clone());
        let scheduler = (!paths.ephemeral).then(|| {
            let executor = Arc::new(crate::daemon::scheduler::ProductionJobExecutor::new(
                db.clone(),
                registry.clone(),
            ));
            let callbacks = executor.callback_registry();
            Arc::new(crate::daemon::scheduler::DaemonScheduler::new(
                db.clone(),
                Arc::new(crate::daemon::scheduler::SystemClock),
                executor,
            ))
            .start_with_callbacks(shutdown.clone(), callbacks)
        });
        if let Some(handle) = &scheduler
            && let Err(error) = crate::skills::curator::register_scheduler(handle, db.clone())
        {
            tracing::warn!(error = %error, "skill curator scheduler registration failed");
        }
        Self {
            db,
            registry,
            paths,
            started_at: Instant::now(),
            caffeinate: Arc::new(crate::daemon::caffeinate::CaffeineController::new()),
            global_events,
            global_redaction,
            terminal_host,
            client_count,
            shutdown,
            shutdown_grace_override: StdMutex::new(None),
            env_baseline: Arc::new(std::sync::RwLock::new(EnvSnapshot::from_process(
                EnvSnapshotSource::DaemonStart,
            ))),
            upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
            connector_wake,
            scheduler,
            credential_store_path: None,
            config_source,
        }
    }

    /// The daemon's config-resolution seam
    /// (`daemon-trust-test-isolation.md`). Request handlers resolve layered
    /// config through this — never directly from disk discovery — so tests
    /// inject configs by parameter instead of relying on the machine's live
    /// `~/.config/cockpit`.
    pub(crate) fn config_source(&self) -> &crate::daemon::config_source::ConfigSource {
        &self.config_source
    }

    #[cfg(test)]
    pub(crate) fn with_credential_store_path(mut self, path: PathBuf) -> Self {
        self.credential_store_path = Some(path);
        self
    }

    pub(crate) fn store_flycockpit_credential(
        &self,
        credential: &crate::auth::flycockpit::StoredFlycockpitCredential,
    ) -> Result<()> {
        if let Some(path) = &self.credential_store_path {
            crate::auth::flycockpit::store_credential_at_path(path.clone(), credential)
        } else {
            crate::auth::flycockpit::store_credential(credential)
        }
    }

    pub(crate) fn clear_flycockpit_credential(&self) -> Result<()> {
        if let Some(path) = &self.credential_store_path {
            crate::auth::flycockpit::clear_credential_at_path(path.clone())
        } else {
            crate::auth::flycockpit::clear_credential()
        }
    }

    /// The daemon's graceful-shutdown gate. New-user-work rejection and the
    /// single drain path both read it.
    pub fn shutdown_signal(&self) -> &crate::daemon::shutdown::ShutdownSignal {
        &self.shutdown
    }

    pub fn set_shutdown_grace_override(&self, grace: Duration) {
        *crate::sync::lock_or_recover(&self.shutdown_grace_override) = Some(grace);
    }

    pub fn take_shutdown_grace_override(&self) -> Option<Duration> {
        crate::sync::lock_or_recover(&self.shutdown_grace_override).take()
    }

    /// Subscribe to the daemon-global event bus. Every client task holds
    /// one of these for its lifetime.
    pub fn subscribe_global(&self) -> EventReceiver {
        self.global_events.subscribe()
    }

    /// Broadcast a daemon-global event to all connected clients.
    pub fn broadcast_global(&self, event: proto::Event) {
        let table = refresh_global_redaction_table(&self.global_redaction);
        send_event(&self.global_events, &table, event);
    }

    async fn resync_caffeinate_state<S>(&self, proto: &mut ProtoStream<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        proto
            .send(&Envelope::event(self.caffeinate_state_event()))
            .await
    }

    async fn resync_drain_state<S>(&self, proto: &mut ProtoStream<S>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        if let Some(event) = self.drain_state_event() {
            proto.send(&Envelope::event(event)).await
        } else {
            Ok(())
        }
    }

    async fn resync_after_global_lag<S>(
        &self,
        proto: &mut ProtoStream<S>,
        attached: Option<&AttachedSession>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.resync_caffeinate_state(proto).await?;
        self.resync_drain_state(proto).await?;
        let _ = attached;
        Ok(())
    }

    /// Subscribe to connector wakeups. Credential store/clear requests use
    /// this to interrupt the connector's fallback polling sleep and any active
    /// relay socket so credential changes take effect immediately.
    pub fn connector_wake_rx(&self) -> watch::Receiver<u64> {
        self.connector_wake.subscribe()
    }

    pub fn wake_connector(&self) {
        self.connector_wake.send_modify(|version| {
            *version = version.wrapping_add(1);
        });
    }

    /// Subscribe to the live connected-client count. Used by the
    /// ephemeral idle watchdog (Layer C).
    pub fn client_presence(&self) -> tokio::sync::watch::Receiver<usize> {
        self.client_count.subscribe()
    }

    /// RAII guard: bumps the connected-client count on construction and
    /// decrements it on drop, so the count stays correct on every exit
    /// path of a client task (clean EOF, decode error, send failure).
    fn track_client(self: &Arc<Self>) -> ClientGuard {
        self.client_count.send_modify(|n| *n += 1);
        ClientGuard { ctx: self.clone() }
    }
}

/// Decrements the daemon's connected-client count when a client task
/// ends, regardless of how it ends.
struct ClientGuard {
    ctx: Arc<DaemonContext>,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.ctx
            .client_count
            .send_modify(|n| *n = n.saturating_sub(1));
    }
}

pub(crate) fn register_in_process_context(ctx: Arc<DaemonContext>) {
    let contexts = IN_PROCESS_CONTEXTS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut contexts = contexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    contexts.insert(ctx.paths.socket.clone(), Arc::downgrade(&ctx));
}

pub(crate) fn in_process_context(socket: &Path) -> Option<Arc<DaemonContext>> {
    let contexts = IN_PROCESS_CONTEXTS.get()?;
    let mut contexts = contexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let weak = contexts.get(socket)?;
    match weak.upgrade() {
        Some(ctx) => Some(ctx),
        None => {
            contexts.remove(socket);
            None
        }
    }
}

/// Bootstrap the daemon: open the DB, build the lock manager, return
/// a ready-to-use context. Called from `daemon::run_foreground`.
pub fn boot(
    paths: DaemonPaths,
    terminal_factory: crate::daemon::terminal::TerminalHostFactory,
) -> Result<DaemonContext> {
    let mut timer = crate::startup::PhaseTimer::start("daemon::boot");
    let db = Db::open_default().context("opening session DB")?;
    let ctx = boot_with_db(paths, db, &mut timer, terminal_factory)?;
    timer.done();
    Ok(ctx)
}

pub(crate) fn boot_with_db(
    paths: DaemonPaths,
    db: Db,
    timer: &mut crate::startup::PhaseTimer,
    terminal_factory: crate::daemon::terminal::TerminalHostFactory,
) -> Result<DaemonContext> {
    timer.phase("db_open_and_migrate");
    let locks = Arc::new(LockManager::from_db(db.clone()).context("loading lock state")?);
    timer.phase("lock_manager");
    run_boot_housekeeping(&db);
    timer.phase("prune_and_sweep");
    let ctx = DaemonContext::new(
        db,
        locks,
        paths,
        terminal_factory,
        crate::daemon::config_source::ConfigSource::production(),
    );
    Ok(ctx)
}

const TERMINAL_REAPER_POLL: Duration = Duration::from_secs(30);

fn spawn_terminal_reaper(
    terminal_host: crate::daemon::terminal::TerminalHostHandle,
    shutdown: crate::daemon::shutdown::ShutdownSignal,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let mut interval = tokio::time::interval(TERMINAL_REAPER_POLL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if shutdown.is_draining() {
                return;
            }
            let closed = terminal_host.sweep_idle(Instant::now());
            if !closed.is_empty() {
                tracing::info!(count = closed.len(), "swept idle remote terminals");
            }
        }
    });
}

fn terminal_temp_root(paths: &DaemonPaths) -> PathBuf {
    paths
        .socket
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(std::env::temp_dir)
        .join("terminal-pastes")
}

fn run_boot_housekeeping(db: &Db) {
    // Drop autocomplete-tally rows that have aged out of the 30-day
    // window. Best-effort — a prune failure shouldn't block boot.
    let before = chrono::Utc::now().timestamp() - crate::db::usage_events::USAGE_WINDOW_SECS;
    if let Err(e) = db.prune_usage_events(before) {
        tracing::warn!(error = %e, "pruning usage_events on boot failed");
    }
    // SIGKILL backstop for `/side`: a side conversation whose owning process
    // died uncatchably can orphan an ephemeral session row. Sweep them on
    // boot so ephemeral sessions never accumulate. Best-effort.
    match db.sweep_ephemeral_sessions() {
        Ok(n) if n > 0 => tracing::info!(count = n, "swept orphaned ephemeral sessions on boot"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "sweeping ephemeral sessions on boot failed"),
    }
    run_retention_pass_blocking(
        db.clone(),
        retention_config(),
        chrono::Utc::now().timestamp(),
    );
    match db.reconcile_orphaned_task_delegations() {
        Ok(n) if n > 0 => {
            tracing::info!(count = n, "marked orphaned task delegations lost on boot")
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "reconciling orphaned task delegations on boot failed")
        }
    }
}

/// Bind the Unix socket and run the accept loop until the daemon's
/// graceful-shutdown gate leaves `Running`. Each accepted connection spawns
/// a detached client task. Breaking the loop hands control back to
/// [`crate::daemon::run_foreground_inner`], which drains the workers.
#[cfg(unix)]
pub async fn run_accept_loop(ctx: Arc<DaemonContext>, listener: UnixListener) -> Result<()> {
    let mut shutdown = ctx.shutdown.subscribe();
    let retention_cfg = retention_config();
    let mut retention_interval = tokio::time::interval(std::time::Duration::from_secs(
        (retention_cfg.sweep_interval_hours.max(1) as u64) * 60 * 60,
    ));
    retention_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    retention_interval.tick().await;
    // A drain may already have begun before we subscribed (begin_drain on a
    // very fast StopDaemon); break immediately if so.
    if ctx.shutdown.is_draining() {
        return Ok(());
    }

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                // Any transition out of `Running` (drain begun) closes the
                // accept loop; `changed()` only errs if the sender dropped,
                // which also means we should stop accepting.
                if changed.is_err() || ctx.shutdown.is_draining() {
                    tracing::info!("daemon: drain begun, closing accept loop");
                    break;
                }
            }
            _ = retention_interval.tick() => {
                run_retention_tick(ctx.clone(), retention_cfg).await;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _peer)) => {
                        if let Err(e) = validate_peer_owner(&stream) {
                            tracing::warn!(error = %e, "rejected daemon socket peer");
                            continue;
                        }
                        let ctx = ctx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, ctx).await {
                                tracing::warn!(error = ?e, "client task ended with error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed; backing off");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }

    Ok(())
}

fn retention_config() -> RetentionConfig {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    ConfigSource::production()
        .load(&cwd)
        .map(|(_, extended)| extended.retention)
        .unwrap_or_default()
}

fn log_retention_outcome(outcome: crate::db::retention::RetentionOutcome) {
    if outcome.sessions_expired > 0 || outcome.payload_rows_deleted > 0 || outcome.vacuumed {
        tracing::info!(
            sessions_expired = outcome.sessions_expired,
            payload_rows_deleted = outcome.payload_rows_deleted,
            vacuumed = outcome.vacuumed,
            "session payload retention pass completed"
        );
    }
}

fn run_retention_pass_blocking(db: Db, cfg: RetentionConfig, now_secs: i64) {
    match db.run_retention_pass(&cfg, now_secs) {
        Ok(outcome) => log_retention_outcome(outcome),
        Err(error) => tracing::warn!(error = %error, "session payload retention pass failed"),
    }
}

async fn run_retention_tick(ctx: Arc<DaemonContext>, cfg: RetentionConfig) {
    run_retention_tick_db(ctx.db.clone(), cfg).await;
}

async fn run_retention_tick_db(db: Db, cfg: RetentionConfig) {
    let now_secs = chrono::Utc::now().timestamp();
    match tokio::task::spawn_blocking(move || db.run_retention_pass(&cfg, now_secs)).await {
        Ok(Ok(outcome)) => log_retention_outcome(outcome),
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "session payload retention pass failed")
        }
        Err(error) => {
            tracing::warn!(error = %error, "session payload retention worker failed")
        }
    }
}

#[cfg(unix)]
fn validate_peer_owner(stream: &UnixStream) -> Result<()> {
    let peer_uid = peer_uid(stream)?;
    let daemon_uid = current_uid();
    validate_peer_uid(peer_uid, daemon_uid)
}

#[cfg(all(unix, target_os = "linux"))]
fn peer_uid(stream: &UnixStream) -> Result<libc::uid_t> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;

    let mut cred = MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into the valid
    // `ucred` storage. We check the return value before reading it.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("reading daemon socket peer uid");
    }

    // SAFETY: `getsockopt` succeeded and initialized the `ucred` struct.
    Ok(unsafe { cred.assume_init().uid })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid(stream: &UnixStream) -> Result<libc::uid_t> {
    use std::os::fd::AsRawFd;

    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    // SAFETY: `getpeereid` writes to valid uid/gid pointers for this socket.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("reading daemon socket peer uid");
    }
    Ok(euid)
}

#[cfg(unix)]
fn current_uid() -> libc::uid_t {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(unix)]
fn validate_peer_uid(peer_uid: libc::uid_t, daemon_uid: libc::uid_t) -> Result<()> {
    if peer_uid != daemon_uid {
        anyhow::bail!(
            "daemon socket peer uid `{peer_uid}` does not match daemon uid `{daemon_uid}`"
        );
    }
    Ok(())
}

// ---- per-client state -----------------------------------------------------

struct ClientState {
    principal: ClientPrincipal,
    attached: Option<AttachedSession>,
    pending_replay: Vec<proto::Event>,
    pending_uploads: HashMap<Uuid, PendingAttachmentUpload>,
    ready_attachments: HashMap<Uuid, ReadyAttachment>,
    upload_accounting: Arc<StdMutex<UploadAccounting>>,
    upload_limits: AttachmentUploadLimits,
    terminal_views: HashSet<Uuid>,
    terminal_host: crate::daemon::terminal::TerminalHostHandle,
}

impl ClientState {
    fn detached_with_principal(
        upload_accounting: Arc<StdMutex<UploadAccounting>>,
        principal: ClientPrincipal,
        terminal_host: crate::daemon::terminal::TerminalHostHandle,
    ) -> Self {
        Self {
            principal,
            attached: None,
            pending_replay: Vec::new(),
            pending_uploads: HashMap::new(),
            ready_attachments: HashMap::new(),
            upload_accounting,
            upload_limits: AttachmentUploadLimits::default(),
            terminal_views: HashSet::new(),
            terminal_host,
        }
    }

    #[cfg(test)]
    fn detached_for_test() -> Self {
        Self::detached_with_principal(
            Arc::new(StdMutex::new(UploadAccounting::default())),
            ClientPrincipal::owner(),
            test_terminal_host(),
        )
    }
}

#[cfg(test)]
fn test_terminal_host() -> crate::daemon::terminal::TerminalHostHandle {
    let (tx, _rx) = broadcast::channel(16);
    crate::daemon::terminal::test_host_factory().build(
        tx,
        Arc::new(std::sync::RwLock::new(Arc::new(RedactionTable::empty()))),
        std::env::temp_dir().join("cockpit-test-terminal-pastes"),
    )
}

impl Drop for ClientState {
    fn drop(&mut self) {
        release_uploads(
            &self.upload_accounting,
            self.pending_uploads.keys().copied(),
        );
        for terminal_id in self.terminal_views.drain() {
            self.terminal_host.release_viewer(terminal_id);
        }
    }
}

const MIN_ATTACHMENT_UPLOAD_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
struct AttachmentUploadLimits {
    per_client_uploads: usize,
    global_uploads: usize,
    per_upload_bytes: usize,
    global_bytes: usize,
}

impl Default for AttachmentUploadLimits {
    fn default() -> Self {
        DaemonUploadLimitsConfig::default().into()
    }
}

impl AttachmentUploadLimits {
    fn from_config(config: DaemonUploadLimitsConfig) -> Self {
        let (limits, warning) = Self::from_config_with_warning(config);
        if let Some(warning) = warning {
            tracing::warn!(%warning, "daemon upload limit adjusted");
        }
        limits
    }

    fn from_config_with_warning(config: DaemonUploadLimitsConfig) -> (Self, Option<String>) {
        let (per_upload_bytes, warning) = normalize_per_upload_bytes(config.per_upload_bytes);
        (
            Self {
                per_client_uploads: config.per_client_uploads,
                global_uploads: config.global_uploads,
                per_upload_bytes,
                global_bytes: config.global_bytes,
            },
            warning,
        )
    }
}

impl From<DaemonUploadLimitsConfig> for AttachmentUploadLimits {
    fn from(config: DaemonUploadLimitsConfig) -> Self {
        Self::from_config(config)
    }
}

fn normalize_per_upload_bytes(configured: usize) -> (usize, Option<String>) {
    if configured > proto::MAX_SINGLE_IMAGE_BYTES {
        return (
            proto::MAX_SINGLE_IMAGE_BYTES,
            Some(format!(
                "per_upload_bytes {} exceeds protocol cap {}; clamping",
                format_upload_bytes(configured),
                format_upload_bytes(proto::MAX_SINGLE_IMAGE_BYTES)
            )),
        );
    }
    if configured < MIN_ATTACHMENT_UPLOAD_BYTES {
        return (
            MIN_ATTACHMENT_UPLOAD_BYTES,
            Some(format!(
                "per_upload_bytes {} is below minimum {}; clamping",
                format_upload_bytes(configured),
                format_upload_bytes(MIN_ATTACHMENT_UPLOAD_BYTES)
            )),
        );
    }
    (configured, None)
}

fn format_upload_bytes(bytes: usize) -> String {
    const MIB: usize = 1024 * 1024;
    const KIB: usize = 1024;
    if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB && bytes.is_multiple_of(KIB) {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} bytes")
    }
}

#[derive(Debug, Default)]
struct UploadAccounting {
    pending: HashMap<Uuid, usize>,
}

impl UploadAccounting {
    fn pending_bytes(&self) -> usize {
        self.pending.values().sum()
    }

    fn reserve(
        &mut self,
        upload_id: Uuid,
        byte_len: usize,
        limits: AttachmentUploadLimits,
    ) -> std::result::Result<(), ErrorPayload> {
        if self.pending.len() >= limits.global_uploads {
            return Err(bad_request(format!(
                "too many pending attachment uploads: daemon has {} pending, limit {}",
                self.pending.len(),
                limits.global_uploads
            )));
        }
        let pending_bytes = self.pending_bytes();
        if pending_bytes.saturating_add(byte_len) > limits.global_bytes {
            return Err(bad_request(format!(
                "pending attachment uploads exceed daemon byte limit: {} + {} bytes exceeds {}",
                pending_bytes, byte_len, limits.global_bytes
            )));
        }
        self.pending.insert(upload_id, byte_len);
        Ok(())
    }

    fn release(&mut self, upload_id: &Uuid) {
        self.pending.remove(upload_id);
    }
}

fn release_uploads<I>(accounting: &Arc<StdMutex<UploadAccounting>>, upload_ids: I)
where
    I: IntoIterator<Item = Uuid>,
{
    let mut accounting = crate::sync::lock_or_recover(accounting);
    for upload_id in upload_ids {
        accounting.release(&upload_id);
    }
}

struct PendingAttachmentUpload {
    session_id: Option<Uuid>,
    mime: String,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
    bytes: Vec<u8>,
    created_at: Instant,
}

struct ReadyAttachment {
    session_id: Uuid,
    mime: String,
    bytes: Vec<u8>,
    purpose: proto::AttachmentPurpose,
    created_at: Instant,
}

struct AttachedSession {
    handle: SessionWorkerHandle,
    event_rx: EventReceiver,
    /// Held for the lifetime of the attachment when this client is
    /// interactive (can answer interrupts). Dropping it on detach /
    /// re-attach / disconnect decrements the worker's interactive-client
    /// count so the loop guard reverts to headless behavior. `None` for a
    /// non-interactive attach (e.g. `cockpit run`'s event pump).
    _interactive_guard: Option<crate::daemon::session_worker::InteractiveClientGuard>,
}

pub(crate) struct InProcessRequest {
    pub request: Request,
    pub reply: oneshot::Sender<std::result::Result<Response, ErrorPayload>>,
}

pub(crate) fn spawn_in_process_client(
    ctx: Arc<DaemonContext>,
) -> (mpsc::Sender<InProcessRequest>, mpsc::Receiver<proto::Event>) {
    let (request_tx, request_rx) = mpsc::channel(IN_PROCESS_REQUEST_QUEUE);
    let (event_tx, event_rx) = mpsc::channel(IN_PROCESS_EVENT_QUEUE);
    tokio::spawn(run_in_process_client(ctx, request_rx, event_tx));
    (request_tx, event_rx)
}

async fn run_in_process_client(
    ctx: Arc<DaemonContext>,
    mut request_rx: mpsc::Receiver<InProcessRequest>,
    event_tx: mpsc::Sender<proto::Event>,
) {
    let _client_guard = ctx.track_client();
    let mut state = ClientState::detached_with_principal(
        ctx.upload_accounting.clone(),
        ClientPrincipal::owner(),
        ctx.terminal_host.clone(),
    );
    let mut global_rx = ctx.subscribe_global();

    if event_tx.send(ctx.caffeinate_state_event()).await.is_err() {
        return;
    }

    loop {
        let event_branch = async {
            match state.attached.as_mut() {
                Some(att) => Some(att.event_rx.recv().await),
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            biased;
            global = global_rx.recv() => {
                match global {
                    Ok(envelope) => {
                        if event_tx.send(envelope.event).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "in-process client global event stream lagged");
                        if event_tx.send(ctx.caffeinate_state_event()).await.is_err() {
                            return;
                        }
                        if let Some(event) = ctx.drain_state_event()
                            && event_tx.send(event).await.is_err()
                        {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {}
                }
            }
            event = event_branch => {
                match event {
                    Some(Ok(envelope)) => {
                        if event_tx.send(envelope.event).await.is_err() {
                            return;
                        }
                    }
                    Some(Err(broadcast::error::RecvError::Lagged(n))) => {
                        tracing::warn!(missed = n, "in-process client event stream lagged; reattach to resync");
                    }
                    Some(Err(broadcast::error::RecvError::Closed)) => {
                        state.attached = None;
                    }
                    None => unreachable!("event_branch is pending when not attached"),
                }
            }
            cmd = request_rx.recv() => {
                let Some(InProcessRequest { request, reply }) = cmd else {
                    return;
                };
                let is_attach = matches!(&request, Request::Attach { .. });
                let result = handle_request(request, &mut state, &ctx).await;
                let attached = matches!(&result, Ok(Response::Attached { .. }));
                let _ = reply.send(result);
                if is_attach && attached {
                    for event in std::mem::take(&mut state.pending_replay) {
                        if event_tx.send(event).await.is_err() {
                            return;
                        }
                    }
                    if let Some(event) = ctx.drain_state_event()
                        && event_tx.send(event).await.is_err()
                    {
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
async fn handle_client(stream: UnixStream, ctx: Arc<DaemonContext>) -> Result<()> {
    handle_client_transport(stream, ctx).await
}

#[allow(dead_code)]
pub(crate) async fn handle_relay_channel<S>(stream: S, ctx: Arc<DaemonContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    handle_relay_channel_as(stream, ctx, ClientPrincipal::owner()).await
}

pub(crate) async fn handle_relay_channel_as<S>(
    stream: S,
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    handle_client_transport_as(stream, ctx, principal).await
}

async fn handle_client_transport<S>(stream: S, ctx: Arc<DaemonContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    handle_client_transport_as(stream, ctx, ClientPrincipal::owner()).await
}

async fn handle_client_transport_as<S>(
    stream: S,
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // Count this client for the lifetime of the task. The guard
    // decrements on every return below (Layer C presence tracking).
    let _client_guard = ctx.track_client();
    let mut proto = ProtoStream::new(stream);

    // Emit a "hello" envelope immediately so cheap probes
    // (`probe_blocking`, third-party reachability checks) can confirm
    // the daemon is alive without doing a full proto handshake. The
    // envelope is a self-contained `DaemonStatus` response with
    // `id = Nil`, which `DaemonClient` ignores (no pending request
    // matches it).
    let hello = Envelope::response(
        Uuid::nil(),
        Response::DaemonStatus {
            pid: std::process::id(),
            uptime_secs: ctx.started_at.elapsed().as_secs(),
            active_sessions: ctx.registry.active_session_ids().len() as u32,
            socket_path: ctx.paths.socket.display().to_string(),
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            paused_sessions: ctx
                .db
                .paused_session_work_all()
                .map(|r| r.len())
                .unwrap_or(0) as u32,
            database_path: ctx
                .db
                .path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<in-memory>".to_string()),
            schema_version: ctx.db.schema_version().unwrap_or(0),
        },
    );
    if proto.send(&hello).await.is_err() {
        return Ok(());
    }

    let mut state = ClientState::detached_with_principal(
        ctx.upload_accounting.clone(),
        principal,
        ctx.terminal_host.clone(),
    );

    // Daemon-global events (caffeinate, …) reach every client regardless
    // of attachment, so this receiver lives for the whole client task.
    let mut global_rx = ctx.subscribe_global();

    // On connect, sync the client's caffeinate glyph to the daemon's
    // current state (a TUI that attaches while caffeination is already on
    // must show ☕ immediately). Fire-and-forget; a send failure just
    // means the client went away.
    let _ = ctx.resync_caffeinate_state(&mut proto).await;

    loop {
        // The select! pulls from whichever side of the socket has work.
        // We have to expand `recv_event` inline because Future<Output=
        // …> from `broadcast::Receiver::recv` borrows the receiver.
        let inbound = async {
            match proto.recv().await {
                Ok(Some(env)) => Some(Ok(env)),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            }
        };

        // If there's an attached session, listen for its events too.
        // When there isn't, the `event_branch` future is `pending`.
        let event_branch = async {
            match state.attached.as_mut() {
                Some(att) => Some(att.event_rx.recv().await),
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            biased;
            global = global_rx.recv() => {
                match global {
                    Ok(envelope) => {
                        let Some(ev) = scrub_event_for_principal(&state.principal, envelope) else {
                            continue;
                        };
                        if let Err(e) = proto.send(&Envelope::event(ev)).await {
                            tracing::debug!(error = ?e, "client disconnected during global event send");
                            return Ok(());
                        }
                    }
                    // A lagging global bus is non-fatal: caffeinate state
                    // and other daemon-global level state are re-synced
                    // immediately so dropped edge events do not leave stale
                    // chrome behind.
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "client global event stream lagged");
                        if ctx
                            .resync_after_global_lag(&mut proto, state.attached.as_ref())
                            .await
                            .is_err()
                        {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // The daemon is tearing down; let the socket close.
                    }
                }
            }
            event = event_branch => {
                match event {
                    Some(Ok(envelope)) => {
                        let Some(ev) = scrub_event_for_principal(&state.principal, envelope) else {
                            continue;
                        };
                        // A raised/resolved interrupt moves the project's
                        // interruptions count. The worker's single forwarder
                        // recomputes and broadcasts the global plan-status
                        // state once per interrupt event; this per-client fan-
                        // out path only forwards the interrupt itself.
                        if let Err(e) = proto.send(&Envelope::event(ev)).await {
                            tracing::debug!(error = ?e, "client disconnected during event send");
                            return Ok(());
                        }
                    }
                    Some(Err(broadcast::error::RecvError::Lagged(n))) => {
                        tracing::warn!(missed = n, "client event stream lagged; reattach to resync");
                        // Per design, lagging clients re-attach. We
                        // emit a synthetic error so the TUI surfaces it.
                        let _ = proto
                            .send(&Envelope::error(
                                None,
                                ErrorPayload {
                                    code: ErrorCode::Internal,
                                    message: format!("event stream lagged by {n}; re-attach"),
                                },
                            ))
                            .await;
                    }
                    Some(Err(broadcast::error::RecvError::Closed)) => {
                        // The session worker exited. Detach so the
                        // client can attach to a different session
                        // without churning.
                        state.attached = None;
                    }
                    None => unreachable!("event_branch is pending when not attached"),
                }
            }
            recv = inbound => {
                match recv {
                    None => return Ok(()), // clean EOF
                    Some(Err(e)) => {
                        tracing::debug!(error = ?e, "envelope decode failed; closing client");
                        return Ok(());
                    }
                    Some(Ok(frame)) => {
                        match frame {
                            RecvFrame::Envelope(env) => {
                                handle_envelope(*env, &mut state, &ctx, &mut proto).await?;
                            }
                            RecvFrame::VersionMismatch { v, kind, id } => {
                                if kind == "req"
                                    && let Some(id) = id
                                {
                                    let envelope = Envelope::error(
                                        Some(id),
                                        ErrorPayload {
                                            code: ErrorCode::ProtocolVersion,
                                            message: proto::version_mismatch_message(v),
                                        },
                                    );
                                    let _ = proto.send(&envelope).await;
                                } else {
                                    tracing::debug!(
                                        version = v,
                                        kind,
                                        ?id,
                                        "closing client after protocol version mismatch"
                                    );
                                }
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn handle_envelope<S>(
    env: Envelope,
    state: &mut ClientState,
    ctx: &Arc<DaemonContext>,
    proto: &mut ProtoStream<S>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    match env.body {
        Body::Request { id, request } => {
            let is_attach = matches!(&request, Request::Attach { .. });
            let result = handle_request(request, state, ctx).await;
            let attached = matches!(&result, Ok(Response::Attached { .. }));
            let envelope = match result {
                Ok(response) => {
                    let response = if state.principal.is_owner() {
                        Some(response)
                    } else if let Some(attached) = state.attached.as_ref() {
                        scrub_proto_response(response, &attached.handle.redaction_table())
                    } else {
                        // Session-bearing responses without an attachment must
                        // scrub inside their request arm using the target
                        // session's persisted table (for example
                        // `SubagentTranscript`). Other unattached responses do
                        // not carry session user content.
                        Some(response)
                    };
                    match response {
                        Some(response) => Envelope::response(id, response),
                        None => Envelope::error(
                            Some(id),
                            ErrorPayload {
                                code: ErrorCode::Internal,
                                message: "response redaction failed".to_string(),
                            },
                        ),
                    }
                }
                Err(err) => Envelope::error(Some(id), err),
            };
            if let Err(error) = proto.send(&envelope).await {
                log_response_send_failed(id, envelope_kind(&envelope), &error);
            }
            if is_attach && attached {
                for event in std::mem::take(&mut state.pending_replay) {
                    if let Err(error) = proto.send(&Envelope::event(event)).await {
                        tracing::debug!(error = ?error, "client disconnected during attach replay");
                        return Ok(());
                    }
                }
                let _ = ctx.resync_drain_state(proto).await;
            }
        }
        Body::Response { id, .. } => {
            tracing::warn!(id = %id, "client sent a response envelope; ignoring");
        }
        Body::Event { event } => {
            tracing::warn!(?event, "client sent an event envelope; ignoring");
        }
        Body::Error { id, error } => {
            tracing::warn!(?id, ?error, "client sent an error envelope; ignoring");
        }
    }
    Ok(())
}

fn envelope_kind(envelope: &Envelope) -> &'static str {
    match envelope.body {
        Body::Response { .. } => "response",
        Body::Error { .. } => "error",
        Body::Request { .. } => "request",
        Body::Event { .. } => "event",
    }
}

fn log_response_send_failed(id: Uuid, envelope_kind: &'static str, error: &anyhow::Error) {
    tracing::warn!(
        request_id = %id,
        envelope_kind,
        error = %error,
        "daemon failed to send response envelope to client"
    );
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: message.into(),
    }
}

fn authorization_error(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Authorization,
        message: message.into(),
    }
}

fn read_only_error(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::ReadOnly,
        message: message.into(),
    }
}

include!("authz.rs");
include!("attachments.rs");
include!("dispatch.rs");
include!("sessions.rs");
include!("tests.rs");
