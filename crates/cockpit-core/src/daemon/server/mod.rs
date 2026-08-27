//! Daemon server — accept loop + per-client task.
//!
//! Bound to the daemon's Unix socket. Each accepted connection spawns
//! a [`handle_client`] task that owns a [`ProtoStream`] and routes
//! requests to / forwards events from the [`SessionRegistry`].
//!
//! See `the design notes` §8 for the architecture and §8c for the wire-schema
//! contract that lets this layer ship without bikeshedding transport.

use std::collections::{HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::Engine as _;
use futures::FutureExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(feature = "remote")]
use tokio::sync::watch;
use tokio::sync::{Semaphore, broadcast, mpsc, oneshot};
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::config::extended::{DaemonUploadLimitsConfig, ExtendedConfig, RetentionConfig};
use crate::daemon::DaemonPaths;
use crate::daemon::config_source::ConfigSource;
use crate::daemon::principal::{self, ClientPrincipal, SessionAccess};
use crate::daemon::proto::{
    self, Body, Envelope, ErrorCode, ErrorPayload, ProtoReadHalf, ProtoStream, ProtoWriteHalf,
    RecvFrame, Request, Response,
};
use crate::daemon::registry::SessionRegistry;
use crate::daemon::scheduler::DaemonSchedulerHandle;
use crate::daemon::session_worker::{SessionWork, SessionWorkerHandle, UserMessageProbeResult};
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
// Per-client task handoff channels are bounded so a stalled socket writer or
// request executor backpressures its producer instead of retaining unbounded
// daemon-global or session events.
const CLIENT_IO_CHANNEL_CAPACITY: usize = 64;
const MAX_CONCURRENT_CLIENT_REQUESTS: usize = 16;

static IN_PROCESS_CONTEXTS: OnceLock<StdMutex<HashMap<PathBuf, RegisteredInProcessContext>>> =
    OnceLock::new();

fn daemon_process_env() -> HashMap<String, String> {
    std::env::vars_os()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        .collect()
}

fn build_daemon_redaction_table(
    config_source: &crate::daemon::config_source::ConfigSource,
    vault: &Arc<crate::secure_key::SecretVault>,
) -> Result<Arc<RedactionTable>> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    let (_, extended) = config_source
        .load(&cwd)
        .context("loading config for daemon redaction")?;
    let cfg = extended.redact;
    let env = daemon_process_env();
    let store = crate::credentials::CredentialStore::from_vault(vault.clone())
        .context("opening daemon vault for redaction")?;
    let built = RedactionTable::build_with_env_and_credential_store(&cfg, &cwd, &env, &store)
        .context("building daemon redaction table")?;
    Ok(Arc::new(built))
}

fn refresh_global_redaction_table(
    shared: &SharedRedactionTable,
    config_source: &crate::daemon::config_source::ConfigSource,
    vault: &Arc<crate::secure_key::SecretVault>,
) -> Result<Arc<RedactionTable>> {
    let fresh = build_daemon_redaction_table(config_source, vault)?;
    let table = Arc::new(
        current_redaction(shared)
            .union(&fresh)
            .context("unioning daemon redaction table")?,
    );
    set_current_redaction(shared, table.clone());
    Ok(table)
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
        // Metadata-only owner-remoted CLI-surface responses: package registry
        // metadata, connector/org-sync state, counts, deletion flags, and
        // structured media-accounting facts carry no free text where a vaulted
        // secret value could hide, so the redaction backstop is a no-op here.
        proto::Response::Packages { .. }
        | proto::Response::PackageAdded { .. }
        | proto::Response::PackageImported { .. }
        | proto::Response::PackagesPruned { .. }
        | proto::Response::KclPackagesImported { .. }
        | proto::Response::EndedSessionsPurged { .. }
        | proto::Response::AssistantDeleted { .. }
        | proto::Response::MediaReservationDiagnosis { .. }
        | proto::Response::MediaReservationRepaired { .. } => {}
        #[cfg(feature = "remote")]
        proto::Response::ConnectorState { .. } | proto::Response::OrgSyncStatus { .. } => {}
        // Free-text-bearing owner-remoted reads: the vaulted-secret redaction
        // backstop scrubs a value that later becomes a credential out of raw
        // tool I/O, compaction event payloads, assistant config, and rendered
        // doctor diagnostics — exactly like the sibling transcript/history
        // responses above. Scrubbing the serialized JSON string replaces any
        // literal secret substring in place and keeps the payload valid JSON.
        proto::Response::FailedToolCalls { calls_json } => scrub_string(calls_json, redact),
        proto::Response::SessionCompactions {
            session_id: _,
            compactions_json,
        } => scrub_string(compactions_json, redact),
        proto::Response::Assistant { assistant } => {
            if let Some(assistant) = assistant {
                scrub_assistant_summary(assistant, redact);
            }
        }
        proto::Response::DoctorSnapshot {
            rendered,
            has_failures: _,
        } => scrub_string(rendered, redact),
        // The docs answer is model-authored free text produced by a read-only
        // package-question pipeline that reads the dependency's real source and
        // the workspace. A vaulted secret value that surfaced in that context
        // must be neutralized before it crosses the socket, exactly like the
        // sibling rendered-doctor / transcript free-text responses above.
        proto::Response::DocsAnswer { answer } => scrub_string(answer, redact),
        // This DTO is constructed from canonical identifiers and fixed
        // redacted diagnostics only; it intentionally excludes workspace
        // paths, source URLs, provider handles, and credentials.
        proto::Response::AgentInstallation(_) => {}
        proto::Response::MediaOwnerRecovery(..)
        | proto::Response::LocalPathMediaRegistration(..)
        | proto::Response::ImageIngressAdmitted(..)
        | proto::Response::RetainedHttpsMedia(..)
        | proto::Response::MediaAttachmentStatus(..)
        | proto::Response::MediaAttachmentPreview(..)
        | proto::Response::LocalMediaMutation(..)
        | proto::Response::MediaUploadStatus(..) => {}
        proto::Response::ConfigRefreshed {
            applied_generation: _,
            changed: _,
        } => {}
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
        | proto::Response::AttachmentUploaded { attachment: _ }
        | proto::Response::NoteRecorded { seq: _ } => {}
        proto::Response::SessionLiveStatus { statuses } => {
            for status in statuses {
                if let Some(project_root) = &mut status.project_root {
                    scrub_string(project_root, redact);
                }
            }
        }
        proto::Response::TerminalOpened {
            terminal_id: _,
            viewer_count: _,
            recording: _,
            binding: _,
            terminal_generation: _,
        }
        | proto::Response::FsWrite { hash: _ }
        | proto::Response::ExtendedConfigSaved { .. }
        | proto::Response::ExtendedConfigWritten { .. }
        | proto::Response::SetupWizardApplied { .. }
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
            persisted_intent: _,
        }
        | proto::Response::SandboxEscalationState { enabled: _ }
        | proto::Response::RedactionState {
            scan_environment: _,
            scan_dotenv: _,
            scan_ssh_keys: _,
        }
        | proto::Response::PreflightState { enabled: _ }
        | proto::Response::LongcacheState { enabled: _ }
        | proto::Response::ApprovalModeState { mode: _ }
        | proto::Response::DelegationRecursionState {
            enabled: _,
            default_depth: _,
        } => {}
        proto::Response::TerminalIngress { receipt: _ } => {}
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
            session_entry_mode: _,
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
        proto::Response::ClientSubmissionReceipt { .. } => {}
        proto::Response::HistoryPage {
            session_id: _,
            entries,
            has_more: _,
            oldest_seq: _,
        } => scrub_history_entries(entries, redact),
        proto::Response::SubagentHistoryPage {
            session_id: _,
            task_call_id: _,
            label,
            entries,
            has_more: _,
            oldest_seq: _,
        } => {
            scrub_string(label, redact);
            scrub_history_entries(entries, redact);
        }
        // Agent-tree snapshots are already constrained durable projections.
        // Their display strings still pass through the normal vault-redaction
        // backstop before a non-owner receives them.
        proto::Response::AgentTreePage { nodes, .. } => {
            for node in nodes {
                scrub_option_string(&mut node.workspace_ref, redact);
            }
        }
        proto::Response::AgentAttentionPage { entries, .. } => {
            for entry in entries {
                scrub_string(&mut entry.options_contract_json, redact);
                scrub_option_string(&mut entry.free_text_contract_json, redact);
                scrub_option_string(&mut entry.recommendation_json, redact);
            }
        }
        proto::Response::AgentDecisionSteered { .. } => {}
        proto::Response::GoalStatus { goal } => {
            if let Some(goal) = goal {
                scrub_goal_summary(goal, redact);
            }
        }
        proto::Response::GoalUpdated { goal } => scrub_goal_summary(goal, redact),
        #[cfg(feature = "remote")]
        proto::Response::RemoteGoalOutcome { .. } => {}
        proto::Response::GoalCleared { cleared: _ } => {}
        proto::Response::Assistants { assistants, .. } => {
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
        proto::Response::InventoryBundle {
            selected_agent: _,
            agents,
            models,
            skills,
            session_generation: _,
            config_generation: _,
            inventory_generation: _,
        } => {
            for skill in skills {
                scrub_skill_summary(skill, redact);
            }
            for agent in agents {
                scrub_agent_summary(agent, redact);
            }
            for model in models {
                scrub_model_summary(model, redact);
            }
        }
        proto::Response::SessionSetupSnapshot { snapshot } => {
            for candidate in &mut snapshot.candidates {
                scrub_string(&mut candidate.installation.source_agent_id, redact);
                scrub_string(&mut candidate.installation.source_identity, redact);
                if let Some(revision) = &mut candidate.installation.source_revision {
                    scrub_string(revision, redact);
                }
                for slot in &mut candidate.slots {
                    for choice in &mut slot.choices {
                        scrub_string(&mut choice.provider_id, redact);
                        scrub_string(&mut choice.model_id, redact);
                        if let Some(label) = &mut choice.author_label {
                            scrub_string(label, redact);
                        }
                        if let Some(rationale) = &mut choice.rationale {
                            scrub_string(rationale, redact);
                        }
                    }
                    for recommendation in &mut slot.unmatched_recommendations {
                        if let Some(label) = &mut recommendation.author_label {
                            scrub_string(label, redact);
                        }
                        if let Some(rationale) = &mut recommendation.rationale {
                            scrub_string(rationale, redact);
                        }
                    }
                }
            }
        }
        proto::Response::AgentEffectiveSettings { snapshot } => {
            // Daemon-owned enums/numbers carry no free text; only the
            // human region labels pass through the vaulted-secret backstop.
            // `region_id` is a stable identity the client echoes back and must
            // never be scrubbed.
            for region in &mut snapshot.verification.regions {
                scrub_string(&mut region.label, redact);
            }
        }
        // Only closed enums, a revision, and daemon-owned ids: nothing to scrub.
        proto::Response::AgentSessionOverrideOutcome { .. } => {}
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
        proto::Response::ExtendedConfigSnapshot {
            layers,
            config_generation: _,
        } => {
            for layer in layers {
                scrub_string(&mut layer.display_path, redact);
                // The authority source already returns a typed, secret-free
                // snapshot (denylist literals and image credentials are
                // replaced before this response is built).  Mutating its
                // strings generically can invalidate enums and typed command
                // structures, so preserve it byte-semantically here.  Opaque
                // capability and revision fields must also remain exact.
                // Fixed display masks and opaque authority fields are protocol
                // constants/capabilities, not free text. Preserve them exact.
            }
        }
        proto::Response::AgentInventory {
            entries,
            inventory_revision,
            ..
        } => {
            for entry in entries {
                scrub_agent_inventory_entry(entry, redact);
            }
            let _ = inventory_revision;
        }
        proto::Response::AgentEditSnapshot(snapshot) => {
            scrub_agent_edit_snapshot(snapshot, redact);
        }
        proto::Response::AgentMutated(result) => {
            if let Some(snapshot) = &mut result.snapshot {
                scrub_agent_edit_snapshot(snapshot, redact);
            }
        }
        proto::Response::AgentEditorLeaseCompleted(_) => {}
        proto::Response::AgentEditorLeaseBegun(lease) => {
            scrub_agent_edit_snapshot(&mut lease.snapshot, redact);
        }
        proto::Response::GitStatus { entries } => {
            for entry in entries {
                scrub_string(&mut entry.raw, redact);
            }
        }
        proto::Response::GitDiffFile { diff, truncated: _ } => scrub_string(diff, redact),
        proto::Response::GitDiff {
            source: _,
            diff,
            truncated: _,
        } => scrub_string(diff, redact),
        proto::Response::GitReviewSources { sources } => {
            for source in sources {
                if let proto::GitReadSource::PullRequest(pr) = &mut source.source {
                    scrub_string(pr, redact);
                }
                scrub_string(&mut source.label, redact);
                if let Some(command) = &mut source.command {
                    scrub_string(command, redact);
                }
                if let Some(error) = &mut source.error {
                    scrub_string(error, redact);
                }
            }
        }
        proto::Response::GitRepoStatus { status } => {
            if let Some(status) = status {
                scrub_string(&mut status.branch, redact);
            }
        }
        proto::Response::WorktreeRoot { root } => {
            if let Some(root) = root {
                scrub_string(root, redact);
            }
        }
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
        proto::Response::RestartDecision {
            will_restart: _,
            reason: _,
        } => {}
        proto::Response::CaffeinateState {
            active: _,
            lid_close_guaranteed: _,
            message,
        } => scrub_string(message, redact),
        proto::Response::PausedWork { items } => scrub_paused_work(items, redact),
        proto::Response::PinChanged { changed: _ }
        | proto::Response::PinToggled { pinned: _ }
        | proto::Response::PinCount { count: _ }
        | proto::Response::PinSeqs { seqs: _ }
        | proto::Response::PinState { state: _ } => {}
        proto::Response::PinsWithText { pins } => {
            for pin in pins {
                scrub_string(&mut pin.text, redact);
            }
        }
        // Sealed-owner sensitive channel responses. The recover-apply success
        // `revealed_literal` is the ONE legitimate remoted plaintext, revealed
        // only to the owner session that minted the capability; it is a
        // redacting/zeroizing literal that must NOT be run through the free-text
        // scrubber (that would corrupt the exact value the owner asked to
        // recover), so this variant's literal field is deliberately OMITTED from
        // scrubbing. Every other sealed-owner response is safe metadata only:
        // capability ids, counts, record/action ids, revisions, enabled flags,
        // and safe descriptions carry no vaulted-secret free text, so the
        // redaction backstop is a no-op. Inventory `name`/`description` are safe
        // Owner-authored metadata (never the literal), matching the
        // secret-free precedent of the sibling leak-report metadata responses.
        proto::Response::SealedOwnerOperationApplied {
            revealed_literal: _,
        }
        | proto::Response::SealedOwnerOperationBegun { .. }
        | proto::Response::SealedOwnerOperationCancelled { .. }
        | proto::Response::SealedOwnerInventory { .. }
        | proto::Response::SealedOwnerDescriptionEdited { .. }
        | proto::Response::SealedActions { .. }
        | proto::Response::SealedActionCreated { .. }
        | proto::Response::SealedActionRevised { .. }
        | proto::Response::SealedActionRetired { .. } => {}
        // Leak responses are secret-free by construction: plaintext, ciphertext,
        // prefix, length, and fingerprint never ride these frames (the reveal
        // plaintext travels only on the protected local sensitive channel), so
        // report ids, rotation disposition, and generation counters carry no
        // free text to scrub.
        proto::Response::LeakReports { page: _ }
        | proto::Response::LeakRevealCapability { capability: _ }
        | proto::Response::LeakRevealCancelled { report_id: _ }
        | proto::Response::LeakRotationUpdated {
            report_id: _,
            rotation: _,
        }
        | proto::Response::LeakReportDeleted { report_id: _ } => {}
        proto::Response::ProjectNotes { notes } => {
            for note in notes {
                scrub_string(&mut note.project_root, redact);
                scrub_string(&mut note.name, redact);
                scrub_string(&mut note.content, redact);
            }
        }
        proto::Response::ProjectNoteCreated { note } => {
            scrub_string(&mut note.project_root, redact);
            scrub_string(&mut note.name, redact);
            scrub_string(&mut note.content, redact);
        }
        proto::Response::ProjectNoteRenamed { name } => scrub_string(name, redact),
        proto::Response::WorkspaceTrustSet {
            config_generation: _,
            live_application_pending: _,
        }
        | proto::Response::WorkspaceTrust { .. }
        | proto::Response::SecretInventory { .. }
        | proto::Response::ProviderCatalogSnapshot { .. }
        | proto::Response::ProviderModelsFetched { .. }
        | proto::Response::ProviderUsageSnapshot { .. }
        | proto::Response::ProviderConfigUpserted { .. }
        | proto::Response::ProviderMutationCommitted { .. }
        | proto::Response::SubscriptionAckCommitted { .. }
        | proto::Response::AppFlag { .. }
        | proto::Response::AppFlagSeen { .. } => {}
        proto::Response::LocalOperationSettlement {
            response,
            terminal_error,
            ..
        } => {
            // Settlement is an envelope around another response. Apply the
            // same backstop recursively so an owner-only nested response can
            // never bypass the principal-specific scrubber when that receipt
            // is later queried by another allowed principal.
            if let Some(response) = response {
                scrub_response_free_text(response, redact);
            }
            if let Some(error) = terminal_error {
                scrub_string(&mut error.message, redact);
            }
        }
        proto::Response::ProviderCredentialCommitted { project_root, .. } => {
            if let Some(root) = project_root {
                scrub_string(root, redact);
            }
        }
        proto::Response::CopilotAuthCommitted { project_root, .. } => {
            scrub_string(project_root, redact);
        }
        #[cfg(feature = "remote")]
        proto::Response::FlycockpitStored
        | proto::Response::FlycockpitNotLoggedIn
        | proto::Response::FlycockpitAccount { .. } => {}
        #[cfg(feature = "remote")]
        proto::Response::FlycockpitAlreadyLoggedIn { email, server_url } => {
            scrub_string(email, redact);
            scrub_string(server_url, redact);
        }
        #[cfg(feature = "remote")]
        proto::Response::FlycockpitCleared { server_url } => {
            scrub_string(server_url, redact);
        }
        #[cfg(feature = "remote")]
        proto::Response::FlycockpitOrgSync { outcome } => {
            if let proto::FlycockpitOrgSyncOutcome::EnrollmentRequired { org_id } = outcome {
                scrub_string(org_id, redact);
            }
        }
        proto::Response::StartupDisclosures {
            org_sync,
            connector,
            config_generation: _,
        } => {
            if let Some(org) = org_sync {
                scrub_string(&mut org.org_id, redact);
            }
            if let Some(connector) = connector {
                scrub_string(&mut connector.status, redact);
                scrub_option_string(&mut connector.relay_url, redact);
                scrub_option_string(&mut connector.relay_id, redact);
                scrub_option_string(&mut connector.relay_region, redact);
                scrub_option_string(&mut connector.last_error, redact);
            }
        }
        proto::Response::AssistantSessionResolved {
            session,
            created: _,
        } => {
            scrub_session_summary(session, redact);
        }
        proto::Response::AssistantUpserted { assistant } => {
            scrub_assistant_summary(assistant, redact)
        }
        proto::Response::AssistantDefinitionSaved { assistant, .. } => {
            if let Some(assistant) = assistant {
                scrub_assistant_summary(assistant, redact);
            }
        }
        proto::Response::ImportSessionArchive { .. } => {}
        // Opaque staged transfer bytes. Redaction is applied when the
        // export is built, not to the base64 body, which must stay
        // byte-exact so its SHA-256 still verifies.
        proto::Response::BulkTransferChunk { .. }
        | proto::Response::BulkTransferChunkAccepted { .. } => {}
        // Content-free run-invocation responses: safe fields only; nothing to scrub.
        proto::Response::RunInvocationStatus { .. }
        | proto::Response::RunInvocationCancelResult { .. }
        | proto::Response::ProviderOAuthCompleted { .. }
        | proto::Response::ProviderOAuthCancelled { .. }
        | proto::Response::McpOAuthCompleted { .. }
        | proto::Response::McpOAuthCancelled { .. } => {}
        proto::Response::McpConfigCommitted {
            project_root,
            config_path,
            ..
        } => {
            scrub_string(project_root, redact);
            scrub_string(config_path, redact);
        }
        #[cfg(feature = "remote")]
        proto::Response::RemoteOperationStatus { .. } => {}
        proto::Response::ProviderOAuthStarted { authorize_url, .. } => {
            scrub_string(authorize_url, redact);
        }
        proto::Response::McpOAuthStarted { authorize_url, .. } => {
            scrub_string(authorize_url, redact);
        }
        proto::Response::HostCapabilities { snapshot } => {
            scrub_host_capability_snapshot(snapshot, redact);
        }
        // Exported policy bundle is opaque serialized config free-text; scrub any
        // known secret value that a caller may have placed inline (defense in
        // depth — the bundle normally carries only `$secret:` references).
        proto::Response::PolicyExported { bundle_json } => {
            scrub_string(bundle_json, redact);
        }
        // Metadata-only: a config file path + counts / typed spend settings /
        // version numbers. No user free-text that could embed a secret.
        proto::Response::PolicyImported { .. } => {}
        #[cfg(feature = "extended")]
        proto::Response::ImageSpendPolicy { .. }
        | proto::Response::ImageSpendPolicySaved { .. } => {}
        // Redacted image-control read reply. Every secret-BEARING field
        // (credential_ref/headers/graph_json/target source_urls) is dropped at
        // the `cockpit_proto::image_control` projection funnel, exactly as the
        // sibling `ProviderCatalogSnapshot` safe projection above excludes its
        // secret material and is likewise not re-scrubbed. The remaining strings
        // are non-secret config identifiers (display names, model names,
        // origins).
        proto::Response::ImageControlRead(..) => {}
        // Redacted image-control config-mutation reply. Its change set carries
        // only `cockpit_proto::image_control` safe projections (credential_ref/
        // headers/graph_json/source_urls are dropped at the projection funnel,
        // exactly like the sibling `ImageControlRead` above), so there is no
        // secret free text to scrub.
        proto::Response::ImageControlMutated(..) => {}
        proto::Response::Unknown => {}
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
        | proto::Event::ActiveModelState { .. }
        | proto::Event::ModelSelectionResult { .. }
        | proto::Event::DefaultModelUpdateResult { .. }
        | proto::Event::PreflightStarted { .. }
        | proto::Event::UserMessagesTerminated { .. }
        | proto::Event::UserMessageRetracted { .. }
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
        | proto::Event::GoalSupervisionProgress {
            session_id: _,
            done: _,
            total: _,
        }
        | proto::Event::LlmModeChanged {
            session_id: _,
            mode: _,
        }
        // Redacted LOCAL image-control `config_changed` event. Its change set
        // carries only the `cockpit_proto::image_control` safe projections
        // (every secret-bearing field — credential_ref/headers/graph_json/
        // source_url — is dropped at the projection funnel, exactly like the
        // sibling `ImageControlRead` response above), so there is no free text
        // to scrub.
        | proto::Event::ImageControlConfigChanged { event: _ }
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
            persisted_intent: _,
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
        | proto::Event::LongcacheState {
            session_id: _,
            enabled: _,
            supported: _,
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
        | proto::Event::Osc52ProtocolViolation {
            terminal_id: _,
            generation: _,
        }
        | proto::Event::EventStreamLagged {
            session_id: _,
            dropped: _,
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
        }
        | proto::Event::AssistantDisplayTextDelta {
            session_id: _,
            agent: _,
            attempt_id: _,
            delta,
        }
        | proto::Event::AssistantDisplayReasoningDelta {
            session_id: _,
            agent: _,
            attempt_id: _,
            delta,
        } => scrub_string(delta, redact),
        proto::Event::AssistantDisplayAttemptReset {
            session_id: _,
            agent: _,
            failed_attempt_id: _,
            replacement_attempt_id: _,
            reason,
        } => scrub_string(reason, redact),
        proto::Event::AssistantDisplayComplete {
            session_id: _,
            agent: _,
            attempt_id: _,
            text,
            presentation_text,
            reasoning,
            seq: _,
            response_performance: _,
        } => {
            scrub_string(text, redact);
            if let Some(presentation) = presentation_text {
                scrub_string(presentation, redact);
            }
            scrub_string(reasoning, redact);
        }
        proto::Event::AssistantDisplayError {
            session_id: _,
            agent: _,
            attempt_id: _,
            kind: _,
            message,
            presentation_text,
        } => {
            scrub_string(message, redact);
            if let Some(presentation) = presentation_text {
                scrub_string(presentation, redact);
            }
        }
        proto::Event::AssistantText {
            session_id: _,
            agent: _,
            text,
            presentation_text,
            reasoning,
            seq: _,
            response_performance: _,
        } => {
            scrub_string(text, redact);
            if let Some(presentation) = presentation_text {
                scrub_string(presentation, redact);
            }
            scrub_string(reasoning, redact);
        }
        proto::Event::UserMessageRecorded {
            session_id: _,
            seq: _,
            client_submission_ids: _,
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
            ..
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
        proto::Event::ToolProgress {
            session_id: _,
            call_id: _,
            done: _,
            total: _,
            unit: _,
        } => {}
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
        #[cfg(feature = "remote")]
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
        proto::Event::HostCapabilitiesChanged { snapshot } => {
            scrub_host_capability_snapshot(snapshot, redact);
        }
        proto::Event::AgentTreeChanged { .. } => {}
        // Session id, durable revision, and a closed state tag: no
        // configuration value, path, or free text can reach a client here.
        proto::Event::WorkspaceTrustReconciliation {
            session_id: _,
            revision: _,
            state: _,
        } => {}
        proto::Event::Unknown => {}
    }
}

fn scrub_host_capability_snapshot(
    snapshot: &mut proto::HostCapabilitySnapshot,
    redact: &RedactionTable,
) {
    for row in &mut snapshot.features {
        scrub_string(&mut row.reason, redact);
        if let Some(fix) = &mut row.fix_command {
            scrub_string(fix, redact);
        }
        if let Some(remedy) = &mut row.remedy_text {
            scrub_string(remedy, redact);
        }
    }
    for row in &mut snapshot.dependencies {
        scrub_string(&mut row.reason, redact);
    }
    if let Some(reason) = &mut snapshot.secret_store.fail_closed_reason {
        scrub_string(reason, redact);
    }
    if let Some(fix) = &mut snapshot.secret_store.fix_command {
        scrub_string(fix, redact);
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
            client_submission_ids: _,
            ts_ms: _,
            seq: _,
            origin_principal: _,
        } => {
            scrub_string(text, redact);
            scrub_option_string(display_text, redact);
            scrub_tag_expansions(tag_expansions, redact);
        }
        proto::HistoryEntry::UserNote {
            text,
            ts_ms: _,
            seq: _,
        } => {
            scrub_string(text, redact);
        }
        proto::HistoryEntry::Assistant {
            agent: _,
            text,
            presentation_text,
            reasoning,
            response_performance: _,
            ts_ms: _,
            seq: _,
        } => {
            scrub_string(text, redact);
            if let Some(presentation) = presentation_text {
                scrub_string(presentation, redact);
            }
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
        session_entry_mode: _,
        short_id: _,
        project_root,
        project_id: _,
        started_at_unix_ms: _,
        last_active_at_unix_ms: _,
        turns: _,
        active_agent: _,
        title,
        parent_session_id: _,
        created_by_principal: _,
        shared_with_collaborators: _,
        fork_count: _,
        descendant_count: _,
        last_viewed_at_unix_ms: _,
        latest_activity_at_unix_ms: _,
        open_interrupts: _,
        activity_state: _,
        archived_at_unix_ms: _,
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
        disposition: _,
        phase: _,
        resume_phase: _,
        pause_reason: _,
        contract_available: _,
        latest_gap_or_blocker,
        verification_attempts: _,
        max_verification_attempts: _,
        attempt_generation: _,
        token_budget: _,
        tokens_used: _,
        remaining_tokens: _,
        elapsed_active_ms: _,
        lifecycle_history: _,
        blocked_attempts: _,
        last_read_at: _,
        created_at: _,
        updated_at: _,
    } = goal;
    scrub_string(project_id, redact);
    scrub_string(objective, redact);
    scrub_option_string(context, redact);
    scrub_option_string(latest_gap_or_blocker, redact);
}

fn scrub_assistant_summary(assistant: &mut proto::AssistantSummary, redact: &RedactionTable) {
    let proto::AssistantSummary {
        name: _,
        created_at: _,
        home_dir,
        config_json,
        definition_presentation_hash: _,
        registration_revision: _,
        definition_markdown,
        definition_revision: _,
        definition_diagnostic,
        projection_digest: _,
    } = assistant;
    scrub_string(home_dir, redact);
    if let Ok(mut config) = serde_json::from_str::<serde_json::Value>(config_json) {
        fn scrub_json(value: &mut serde_json::Value, redact: &RedactionTable) {
            match value {
                serde_json::Value::String(value) => scrub_string(value, redact),
                serde_json::Value::Array(values) => {
                    values
                        .iter_mut()
                        .for_each(|value| scrub_json(value, redact));
                }
                serde_json::Value::Object(values) => {
                    values
                        .values_mut()
                        .for_each(|value| scrub_json(value, redact));
                }
                _ => {}
            }
        }
        scrub_json(&mut config, redact);
        if let Ok(redacted) = serde_json::to_string(&config) {
            *config_json = redacted;
        }
    }
    scrub_option_string(definition_markdown, redact);
    scrub_option_string(definition_diagnostic, redact);
}

fn scrub_agent_inventory_entry(entry: &mut proto::AgentInventoryEntry, redact: &RedactionTable) {
    scrub_option_string(&mut entry.description, redact);
    scrub_option_string(&mut entry.model, redact);
    scrub_option_string(&mut entry.diagnostic, redact);
}

fn scrub_agent_edit_snapshot(snapshot: &mut proto::AgentEditSnapshot, redact: &RedactionTable) {
    scrub_string(&mut snapshot.markdown, redact);
    scrub_string(&mut snapshot.canonical_preview, redact);
    scrub_option_string(&mut snapshot.goal_supervision_json, redact);
}

/// Mint presentation digests only after the final socket-bound redaction
/// pass. This is infallible and therefore cannot turn a committed mutation
/// into a post-commit response error.
fn finalize_response_projections(
    response: &mut proto::Response,
    vault: &crate::secure_key::SecretVault,
) {
    fn keyed(vault: &crate::secure_key::SecretVault, domain: &[u8], value: &[u8]) -> String {
        crate::intel::hex_lower(&vault.keyed_identity(domain, value))
    }
    fn assistant(value: &mut proto::AssistantSummary, vault: &crate::secure_key::SecretVault) {
        value.definition_presentation_hash = value.definition_markdown.as_ref().map(|markdown| {
            keyed(
                vault,
                b"flycockpit.assistant.presentation.v1",
                markdown.as_bytes(),
            )
        });
        let material = proto::assistant_projection_material(value);
        value.projection_digest = keyed(
            vault,
            b"flycockpit.assistant.projection.v1",
            material.as_bytes(),
        );
    }
    fn agent(value: &mut proto::AgentEditSnapshot, vault: &crate::secure_key::SecretVault) {
        let material = proto::agent_edit_projection_material(value);
        value.projection_digest = keyed(
            vault,
            b"flycockpit.agent.edit-projection.v1",
            material.as_bytes(),
        );
    }
    match response {
        proto::Response::Assistant {
            assistant: Some(value),
        } => assistant(value, vault),
        proto::Response::Assistants { assistants, .. } => assistants
            .iter_mut()
            .for_each(|value| assistant(value, vault)),
        proto::Response::AssistantUpserted { assistant: value } => assistant(value, vault),
        proto::Response::AssistantDefinitionSaved {
            assistant: Some(value),
            ..
        } => assistant(value, vault),
        proto::Response::AgentInventory { entries, .. } => {
            for entry in entries {
                let material = proto::agent_inventory_entry_projection_material(entry);
                entry.projection_digest = keyed(
                    vault,
                    b"flycockpit.agent.inventory-projection.v1",
                    material.as_bytes(),
                );
            }
        }
        proto::Response::AgentEditSnapshot(value) => agent(value, vault),
        proto::Response::AgentMutated(result) => {
            if let Some(value) = &mut result.snapshot {
                agent(value, vault);
            }
        }
        proto::Response::AgentEditorLeaseCompleted(_) => {}
        proto::Response::AgentEditorLeaseBegun(lease) => agent(&mut lease.snapshot, vault),
        _ => {}
    }
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
        trust: _,
        reasoning_effort: _,
        thinking_modes: _,
        available: _,
        native_provider_valid: _,
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
        | proto::AuthFailureKind::ProviderNotConfigured
        | proto::AuthFailureKind::Other(_) => {}
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
        image_plan_review,
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
    // The plan review carries only redacted projections by construction, but
    // pass its user-derivable strings through the same scrubber for defense in
    // depth.
    if let Some(review) = image_plan_review {
        scrub_option_string(&mut review.plan_digest, redact);
        scrub_strings(&mut review.destination_location_classes, redact);
        scrub_option_string(&mut review.output_location_class, redact);
        scrub_option_string(&mut review.reference_egress_summary, redact);
        for disposition in &mut review.budget_dispositions {
            scrub_string(&mut disposition.scope, redact);
            scrub_string(&mut disposition.disposition, redact);
        }
    }
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
        denial,
    } = escalation;
    scrub_string(confined_stderr, redact);
    scrub_strings(suggested_paths, redact);
    scrub_option_string(suggested_access, redact);
    if let Some(denial) = denial {
        scrub_sandbox_denial_report(denial, redact);
    }
}

fn scrub_sandbox_denial_report(report: &mut proto::SandboxDenialReport, redact: &RedactionTable) {
    for evidence in &mut report.evidence {
        match evidence {
            proto::SandboxDenialEvidence::WriteOutsideAllowlist { path }
            | proto::SandboxDenialEvidence::ReadOutsideAllowlist { path } => {
                scrub_string(path, redact);
            }
            proto::SandboxDenialEvidence::StderrPermissionMarker
            | proto::SandboxDenialEvidence::Unknown { .. } => {}
        }
    }
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
    /// Shared durable media authority. Production media entry points consult
    /// `media_admission_open` before accepting work.
    pub media_ledger: crate::media_reservation::MediaReservationLedger,
    pub media_admission_open: Arc<std::sync::atomic::AtomicBool>,
    pub registry: SessionRegistry,
    pub paths: DaemonPaths,
    /// Canonical process cwd captured once at daemon construction. Remote
    /// operation resources never trust a caller-supplied fallback cwd.
    pub canonical_cwd: PathBuf,
    #[cfg(test)]
    pub(crate) fcor_resolver_calls: std::sync::atomic::AtomicUsize,
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
    /// Vault inventory generation reflected by the currently published
    /// `global_redaction` table. `broadcast_global` rebuilds the table only
    /// when the live vault generation has advanced past this value, so a
    /// direct/cross-process vault write still refreshes redaction while a
    /// bursty broadcast with no vault change stays cheap. `0` forces a rebuild
    /// on the first broadcast after construction.
    redaction_generation: std::sync::atomic::AtomicU64,
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
    /// Serializes idle restart decisions so exactly one client can pair
    /// "daemon is idle" with the monotonic shutdown-gate transition.
    pub(crate) restart_decision: StdMutex<()>,
    shutdown_grace_override: StdMutex<Option<Duration>>,
    env_baseline: Arc<std::sync::RwLock<EnvSnapshot>>,
    upload_accounting: Arc<StdMutex<UploadAccounting>>,
    #[cfg(feature = "remote")]
    connector_wake: watch::Sender<u64>,
    /// Serializes a remote operation identity from admission through every
    /// external side effect and its transactional replay commit. Different
    /// request hashes intentionally share the same key: the conflict loser
    /// must learn that it lost before it can stop workers or touch media.
    #[cfg(feature = "remote")]
    remote_operation_locks: tokio::sync::Mutex<HashMap<(Uuid, Uuid), Weak<tokio::sync::Mutex<()>>>>,
    pub scheduler: Option<DaemonSchedulerHandle>,
    /// Stable, nonzero daemon boot UUID for all image-generation scheduler
    /// passes and deadline observation. The lifecycle worker uses it as its
    /// `worker_boot_id`; a job-creation caller uses it as the plan's
    /// `deadline_boot_id` so a job queued this boot is dispatchable this boot and
    /// a pre-crash boot's monotonic deadlines are never revived.
    image_generation_boot_id: Uuid,
    /// Handle to the daemon-lifecycle image-generation worker (non-ephemeral
    /// start only). Held for the daemon's lifetime; the worker exits
    /// cooperatively when the shutdown gate drains.
    _image_generation_worker: Option<tokio::task::JoinHandle<()>>,
    #[allow(dead_code)]
    credential_store_path: Option<PathBuf>,
    /// Daemon-held wrap-key vault. Flycockpit credential persist uses this
    /// handle; leftover `credentials.json` is never consulted.
    pub(crate) secret_vault: Arc<crate::secure_key::SecretVault>,
    /// Daemon-owned, in-memory sealed-owner capability table. `Begin` mints a
    /// capability here bound to the minting connection's `client_instance_id`;
    /// `Apply`/`Cancel` enforce the minting-session match and drive the shared
    /// compare-and-swap. In-memory only: a daemon restart invalidates every
    /// outstanding capability (fail-closed), and no capability or literal ever
    /// touches disk.
    pub(crate) sealed_owner_capabilities:
        Arc<StdMutex<sealed_capabilities::SealedOwnerCapabilityTable>>,
    /// Context-owned bounded OAuth state; never process-global.
    pub(crate) oauth_flows: Arc<dispatch::OAuthFlowStore>,
    /// Injectable config-resolution seam (`daemon-trust-test-isolation.md`):
    /// the single route by which request handling resolves layered
    /// provider/extended config. Shared with the registry so attach-create,
    /// resume, and worker startup all consult the same source.
    config_source: crate::daemon::config_source::ConfigSource,
    /// A debug-build-only scripted agent-installation coordinator.  It is
    /// built once at daemon boot from an explicit non-secret fixture file and
    /// reused by every agent RPC so a Begin continuation and SubmitChoice
    /// always see the identical fetcher/catalog/workspace authority.
    #[cfg(debug_assertions)]
    agent_installation_fixture:
        Option<Arc<crate::daemon::agent_installation::AgentInstallationService>>,
    /// Daemon-owned native secure key actor (`native-secure-key-store`).
    /// Started under the single-instance lock after installation identity
    /// is loaded; process-global keyring registration is drained on drop.
    pub secure_key: Option<crate::secure_key::SecureKeyHandle>,
    /// Owns the actor thread; kept so Drop drains before unset_default_store.
    _secure_key_actor: Option<crate::secure_key::SecureKeyActor>,
    /// Shared production protected redaction-history key resolver, built from
    /// [`Self::secure_key`] when the actor attaches and also installed on the
    /// registry so every session shares one cache. `None` in production until
    /// the actor attaches; unit tests (which never start the native actor) seed
    /// a real test resolver in [`Self::new`]. Consumers that require it fail
    /// closed via [`Self::redaction_key_resolver`].
    redaction_key_resolver:
        Option<Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>>,
    /// Generic durable journal for ambiguous external side effects
    /// (`external-side-effect-journal`). `None` until startup recovery has run
    /// and revalidated recovery capacity; every consumer must treat `None` as
    /// "external dispatch is not enabled".
    pub external_journal: Option<std::sync::Arc<crate::external_journal::ExternalJournal>>,
    /// Boot-held authority for the fixed private media component root.
    pub(crate) media_storage_recovery:
        Option<std::sync::Arc<crate::media_storage::MediaStorageRecovery>>,
    /// Generation-bound descendant containment (`cross-platform-descendant-process-containment`).
    pub process_containment: Option<crate::process_containment::ProcessContainmentHandle>,
    _process_containment_actor: Option<crate::process_containment::ProcessContainmentActor>,
    /// Durable hierarchical write-scope authority (`spawn-scoped-writes`).
    /// `None` under unit tests, which opt in explicitly. Every consumer must
    /// treat `None` as "no durable write-scope lifecycle is available", which is
    /// safe because the spawn gate independently refuses writable delegation.
    pub write_scope: Option<std::sync::Arc<crate::write_scope::WriteScopeCoordinator>>,
    /// Leak-reveal capability slot + successful-reveal rate window, behind one
    /// mutex. In-memory only: a daemon restart invalidates outstanding
    /// capabilities (fail-closed), and secrets-adjacent tokens never touch disk.
    /// Single slot ⇒ one reveal in flight; minting replaces the prior token.
    pub(crate) leak_reveal_state: Arc<StdMutex<crate::leaks::LeakRevealState>>,
    /// Per-daemon-boot random 32-byte HMAC key for the leak-list cursor. Rotated
    /// on restart, so stale cursors fail closed into a fresh snapshot.
    pub(crate) leak_cursor_key: [u8; 32],
    /// Deny-closed resolver mapping a canonical local project root to the
    /// 16-byte control-plane project id an attempt-grant permission ceiling is
    /// keyed by. Consulted only on the `RemoteAuthorization::AttemptGrant`
    /// authorization path; an unmapped root fails closed (never a best-effort
    /// root hash). The default is an empty deny-all resolver; production wiring
    /// against attachment/operation-ledger state is owned by the
    /// transport-wiring prompts.
    #[cfg(feature = "remote")]
    pub remote_project_resolver:
        Arc<dyn crate::daemon::remote_project_resolver::RemoteProjectResolver>,
    /// Daemon-owned host capability snapshot. Authority for feature gating.
    /// The TUI in-process doctor compose is not this store.
    pub(crate) host_capabilities: crate::host_capabilities::HostCapabilitySnapshotStore,
    /// Probe sources used by boot and `RefreshHostCapabilities`.
    pub(crate) host_capability_probes: crate::host_capabilities::HostCapabilityProbeInputs,
    /// A post-commit redaction publication failure means the daemon cannot
    /// safely serve another request with its stale in-memory table.  This is
    /// deliberately sticky until process restart.
    redaction_publication_poisoned: AtomicBool,
    /// Context-scoped test failpoint; unlike process-global state it cannot
    /// make a parallel test daemon fail spuriously.
    #[cfg(test)]
    redaction_refresh_failure: Arc<AtomicBool>,
}

#[cfg(test)]
pub(crate) fn test_context_for_daemon_modules() -> Arc<DaemonContext> {
    let db = Db::open_in_memory().expect("in-memory test db");
    let locks = Arc::new(crate::locks::LockManager::in_memory(db.clone()));
    Arc::new(DaemonContext::new(
        db,
        locks,
        DaemonPaths {
            socket: PathBuf::from("/tmp/cockpit-module-test.sock"),
            pid_file: PathBuf::from("/tmp/cockpit-module-test.pid"),
            ephemeral: true,
        },
        crate::daemon::terminal::test_host_factory(),
        crate::daemon::config_source::ConfigSource::fixed(
            crate::config::providers::ProvidersConfig::default(),
            crate::config::extended::ExtendedConfig::default(),
        ),
    ))
}

impl DaemonContext {
    pub(crate) fn current_global_redaction(&self) -> Arc<RedactionTable> {
        current_redaction(&self.global_redaction)
    }
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
        let daemon_cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let canonical_cwd = daemon_cwd.canonicalize().unwrap_or(daemon_cwd);
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
        // Production installs the real resolver when the secure-key actor
        // attaches (`attach_secure_key_actor`), which tests skip. Give the
        // registry and this context a real test resolver so session builds and
        // resume fallbacks succeed in tests without the native actor (decision
        // 16 — never absent, never `Option` at the point of use).
        #[cfg(test)]
        let redaction_key_resolver: Option<
            Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
        > = {
            let resolver = crate::session::test_redaction_key_resolver();
            registry.set_redaction_key_resolver(resolver.clone());
            Some(resolver)
        };
        #[cfg(not(test))]
        let redaction_key_resolver: Option<
            Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>,
        > = None;
        let (client_count, _) = tokio::sync::watch::channel(0usize);
        #[cfg(feature = "remote")]
        let (connector_wake, _) = watch::channel(0u64);
        let (global_events, _) = broadcast::channel(GLOBAL_EVENT_CAPACITY);
        let secret_vault = crate::secure_key::open_for_db(&db)
            .unwrap_or_else(|error| panic!("daemon vault required at construction: {error}"));
        registry.set_secret_vault(secret_vault.clone());
        config_source.install_vault(secret_vault.clone());
        let global_redaction = Arc::new(std::sync::RwLock::new(
            build_daemon_redaction_table(&config_source, &secret_vault).unwrap_or_else(|error| {
                panic!("daemon redaction table required at construction: {error}")
            }),
        ));
        // MCP connections retain only the vault handle, not the full daemon
        // context. Install the owner publication seam here so an in-band
        // OAuth refresh cannot commit a new token while leaving the active
        // daemon redaction table stale. A Weak avoids a vault↔callback cycle.
        let redaction_vault = Arc::downgrade(&secret_vault);
        let redaction_config_source = config_source.clone();
        let redaction_shared = global_redaction.clone();
        secret_vault.install_owner_redaction_publisher(Arc::new(move || {
            let vault = redaction_vault
                .upgrade()
                .ok_or_else(|| "daemon vault is no longer available".to_string())?;
            refresh_global_redaction_table(&redaction_shared, &redaction_config_source, &vault)
                .map(|_| ())
                .map_err(|error| error.to_string())
        }));
        #[cfg(debug_assertions)]
        let agent_installation_fixture =
            crate::daemon::agent_installation::debug_fixture_daemon_service(db.clone(), &paths)
                .unwrap_or_else(|error| {
                    panic!("invalid debug agent-installation fixture: {error:#}")
                })
                .map(Arc::new);
        let terminal_host = terminal_factory.build(
            global_events.clone(),
            global_redaction.clone(),
            terminal_temp_root(&paths),
        );
        let container = Arc::new(crate::container::ContainerManager::detect());
        let _ = crate::container::container_manager().set((*container).clone());
        spawn_terminal_reaper(terminal_host.clone(), shutdown.clone());
        crate::daemon::bulk_staging::spawn_reaper(shutdown.clone());
        registry
            .lsp_manager()
            .set_notice_bus(global_events.clone(), global_redaction.clone());
        registry.set_global_bus(global_events.clone());
        #[cfg(feature = "extended")]
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
        #[cfg(not(feature = "extended"))]
        let scheduler: Option<crate::daemon::scheduler::DaemonSchedulerHandle> = None;
        if let Some(handle) = &scheduler {
            registry.set_scheduler(handle.clone());
        }
        let host_capabilities = crate::host_capabilities::HostCapabilitySnapshotStore::new();
        let host_capability_probes =
            crate::host_capabilities::HostCapabilityProbeInputs::production(canonical_cwd.clone());
        registry.set_host_capabilities(host_capabilities.clone(), host_capability_probes.clone());
        struct DaemonMediaClock(Instant);
        impl crate::media_reservation::MonotonicClock for DaemonMediaClock {
            fn now_ms(&self) -> u64 {
                u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
            }
        }
        let started_at = Instant::now();
        let media_ledger = crate::media_reservation::MediaReservationLedger::new(
            db.clone(),
            Arc::new(DaemonMediaClock(started_at)),
        );
        let media_storage_recovery = (!paths.ephemeral)
            .then(|| crate::config::resolve::cockpit_data_dir().map(|dir| dir.join("media")))
            .transpose()
            .ok()
            .flatten()
            .and_then(|root| {
                crate::media_storage::MediaStorageRecovery::open_or_create(db.clone(), &root).ok()
            })
            .map(Arc::new);
        if let Some(storage) = &media_storage_recovery {
            registry.set_message_media_authority(storage.clone(), media_ledger.clone());
        }
        // One stable, nonzero daemon boot UUID drives every image-generation
        // scheduler pass and deadline observation. The lifecycle worker below
        // uses it as `worker_boot_id`; a job-creation caller uses it as the
        // plan's `deadline_boot_id`.
        let image_generation_boot_id = Uuid::now_v7();
        // Spawn the daemon-lifecycle image-generation worker on NON-ephemeral
        // start only (same gating as the scheduler / media-ledger install). It
        // shares `started_at` so its monotonic clock matches the media ledger and
        // sealed plan deadlines. This increment ships an empty adapter map and no
        // resolved destinations; concrete provider adapters + the destination map
        // install with the wire-adapters / real-dispatch prompts, so a queued job
        // records a typed `adapter_missing` skip rather than dispatching.
        #[cfg(feature = "extended")]
        let image_generation_worker = (!paths.ephemeral)
            .then(|| {
                match crate::daemon::image_runtime::install_standard_image_runtime_registry(
                    &cockpit_config::config::image_generation::ImageGenerationConfig::default(),
                    1,
                    1,
                    None,
                ) {
                    Ok(registry) => {
                        let proof_source = Arc::new(
                            crate::image_generation_job::RegistryDispatchProofSource::new(
                                registry,
                                std::collections::HashMap::new(),
                            ),
                        );
                        Some(
                            crate::daemon::image_generation_worker::spawn_image_generation_worker(
                                db.clone(),
                                image_generation_boot_id,
                                started_at,
                                crate::image_generation_job::ImageGenerationAdapterMap::new(),
                                proof_source,
                                shutdown.clone(),
                            ),
                        )
                    }
                    Err(error) => {
                        tracing::error!(
                            %error,
                            "image generation runtime registry unavailable; worker not started"
                        );
                        None
                    }
                }
            })
            .flatten();
        #[cfg(not(feature = "extended"))]
        let image_generation_worker = None;
        Self {
            db,
            media_ledger,
            media_admission_open: Arc::new(std::sync::atomic::AtomicBool::new(cfg!(test))),
            registry,
            paths,
            canonical_cwd: canonical_cwd.clone(),
            #[cfg(test)]
            fcor_resolver_calls: std::sync::atomic::AtomicUsize::new(0),
            started_at,
            caffeinate: Arc::new(crate::daemon::caffeinate::CaffeineController::new()),
            global_events,
            global_redaction,
            redaction_generation: std::sync::atomic::AtomicU64::new(0),
            terminal_host,
            client_count,
            shutdown,
            restart_decision: StdMutex::new(()),
            shutdown_grace_override: StdMutex::new(None),
            env_baseline: Arc::new(std::sync::RwLock::new(EnvSnapshot::from_process(
                EnvSnapshotSource::DaemonStart,
            ))),
            upload_accounting: Arc::new(StdMutex::new(UploadAccounting::default())),
            #[cfg(feature = "remote")]
            connector_wake,
            #[cfg(feature = "remote")]
            remote_operation_locks: tokio::sync::Mutex::new(HashMap::new()),
            scheduler,
            image_generation_boot_id,
            _image_generation_worker: image_generation_worker,
            credential_store_path: None,
            secret_vault,
            sealed_owner_capabilities: Arc::new(StdMutex::new(
                sealed_capabilities::SealedOwnerCapabilityTable::default(),
            )),
            oauth_flows: Arc::new(dispatch::OAuthFlowStore::new()),
            config_source,
            #[cfg(debug_assertions)]
            agent_installation_fixture,
            secure_key: None,
            _secure_key_actor: None,
            redaction_key_resolver,
            external_journal: None,
            media_storage_recovery,
            process_containment: None,
            _process_containment_actor: None,
            write_scope: None,
            leak_reveal_state: Arc::new(StdMutex::new(crate::leaks::LeakRevealState::new())),
            leak_cursor_key: crate::leaks::random_cursor_key(),
            // Deny-all default: an empty resolver maps no root, so the
            // attempt-grant authorization path fails closed until the
            // transport-wiring prompts install the real resolver.
            #[cfg(feature = "remote")]
            remote_project_resolver: Arc::new(
                crate::daemon::remote_project_resolver::StaticRemoteProjectResolver::new(),
            ),
            host_capabilities,
            host_capability_probes,
            redaction_publication_poisoned: AtomicBool::new(false),
            #[cfg(test)]
            redaction_refresh_failure: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Install the deny-closed remote project resolver consulted by the
    /// attempt-grant authorization path. Production transport-wiring installs a
    /// resolver backed by attachment/operation-ledger state; tests inject a
    /// deterministic static mapping. The resolver never widens authority: an
    /// unmapped root fails closed.
    #[cfg(feature = "remote")]
    pub fn with_remote_project_resolver(
        mut self,
        resolver: Arc<dyn crate::daemon::remote_project_resolver::RemoteProjectResolver>,
    ) -> Self {
        self.remote_project_resolver = resolver;
        self
    }

    /// Install the secure-key actor after identity creation. Production always
    /// resolves KEK placement and attaches the actor when placement can be
    /// established. Keyring-down after `active_placement=keyring` is
    /// `KekUnavailable` (no file-KEK fallback).
    #[cfg_attr(test, allow(dead_code))] // production boot only; tests skip native actor start
    pub(crate) fn attach_secure_key_actor(&mut self, actor: crate::secure_key::SecureKeyActor) {
        let handle = actor.handle();
        // Build the one shared protected redaction-history key resolver over the
        // daemon's secure-key handle (decision 9.5.1) and install it on the
        // registry so every session it builds shares this cache. The leak-report
        // provider containment barrier reaches the same resolver per session via
        // `Session::redaction_key_resolver`.
        let resolver: Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver> =
            Arc::new(crate::redact::secure_key_resolver::SecureKeyResolver::new(
                handle.clone(),
            ));
        self.registry.set_redaction_key_resolver(resolver.clone());
        if let Some(storage) = self.media_storage_recovery.clone() {
            self.registry.set_tool_media_runtime(Arc::new(
                crate::tool_media_authority::runtime::ToolMediaRuntime::new(
                    handle.clone(),
                    storage,
                ),
            ));
        }
        self.redaction_key_resolver = Some(resolver);
        self.secure_key = Some(handle);
        self._secure_key_actor = Some(actor);
    }

    /// Resolve every command-backed named secret referenced by the daemon's
    /// configured provider headers into the process cache at startup
    /// (`daemon_startup_resolves_referenced_command_secrets`). Referenced names
    /// end up `Resolved` or `Failed` in the cache; a failure lands as `Failed`
    /// and NEVER fails boot — the first outbound request then observes the cached
    /// status (missing / auth error), never a sync exec. Called once from
    /// `boot_with_db`, after the secure-key actor has attached.
    pub(crate) async fn resolve_startup_command_secrets(&self) {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
        // Trust-gate the config load: a daemon launched inside an UNTRUSTED
        // repository must not read that repo's project-layer provider headers
        // and exec their `$secret:` command references at boot. Loading under
        // the DB-resolved workspace trust policy drops untrusted project layers,
        // so only trusted (workspace/global) references reach resolution.
        let trust_policy = match crate::config::trust::resolve_workspace_trust_policy_from_db(
            &self.db, &cwd,
        )
        .await
        {
            Ok(policy) => policy,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "startup command-secret resolution skipped: workspace trust policy unavailable"
                );
                return;
            }
        };
        let providers = match self
            .config_source
            .load_effective_for_daemon(&cwd, &trust_policy)
        {
            Ok((providers, _extended)) => providers,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "startup command-secret resolution skipped: provider config load failed"
                );
                return;
            }
        };
        let names = crate::secret_ref::provider_named_secret_references(&providers);
        // Owner-scoped by (provider, cwd): only already-claimed command names
        // resolve; a foreign / unclaimed name is dropped and never execed.
        self.registry
            .resolve_provider_command_secrets(&cwd.display().to_string(), &names, false)
            .await;
    }

    /// The shared production redaction key resolver, or a fail-closed error when
    /// the secure-key actor never attached (decision 16 — required, never
    /// `Option` at the point of use).
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn redaction_key_resolver(
        &self,
    ) -> Result<Arc<dyn crate::redact::protected_redaction_history::RedactionKeyResolver>> {
        self.redaction_key_resolver.clone().context(
            "protected redaction-history key resolver unavailable (secure-key actor not started)",
        )
    }
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn attach_process_containment_actor(
        &mut self,
        actor: crate::process_containment::ProcessContainmentActor,
    ) {
        self.process_containment = Some(actor.handle());
        self._process_containment_actor = Some(actor);
    }

    /// The daemon's config-resolution seam
    /// (`daemon-trust-test-isolation.md`). Request handlers resolve layered
    /// config through this — never directly from disk discovery — so tests
    /// inject configs by parameter instead of relying on the machine's live
    /// `~/.config/cockpit`.
    pub(crate) fn config_source(&self) -> &crate::daemon::config_source::ConfigSource {
        &self.config_source
    }

    /// Return the one debug-fixture coordinator when explicitly enabled, or
    /// construct the normal daemon-owned service.  The fixture branch is
    /// absent from release builds, so setting its environment variable there
    /// has no effect.
    pub(crate) fn agent_installation_service(
        &self,
    ) -> Result<Arc<crate::daemon::agent_installation::AgentInstallationService>> {
        self.agent_installation_service_for_authorized_workspace(None)
    }

    /// Construct the installation boundary with the already-attached
    /// session's workspace proof in the local-owner authorization contract.
    /// The caller receives that immutable proof only from a daemon-owned
    /// attachment, never from request data or a later path lookup.
    pub(crate) fn agent_installation_service_for_authorized_workspace(
        &self,
        attached_workspace_root: Option<
            &crate::daemon::agent_installation::AuthorizedWorkspaceRoot,
        >,
    ) -> Result<Arc<crate::daemon::agent_installation::AgentInstallationService>> {
        self.agent_installation_service_for_authorized_workspace_with_providers(
            attached_workspace_root,
            None,
        )
    }

    /// Same installation boundary, but lets a read-only projection reuse the
    /// attached worker's already-authoritative provider snapshot. This avoids
    /// reopening `canonical_cwd` while a setup request holds an attach-time
    /// workspace capability.
    pub(crate) fn agent_installation_service_for_authorized_workspace_with_providers(
        &self,
        attached_workspace_root: Option<
            &crate::daemon::agent_installation::AuthorizedWorkspaceRoot,
        >,
        providers: Option<crate::config::providers::ProvidersConfig>,
    ) -> Result<Arc<crate::daemon::agent_installation::AgentInstallationService>> {
        #[cfg(debug_assertions)]
        if let Some(service) = &self.agent_installation_fixture {
            return Ok(service.clone());
        }
        let authorized_roots = match attached_workspace_root {
            // If the session was attached at the daemon cwd, do not capture
            // that spelling again: a replacement directory would otherwise
            // be accidentally admitted alongside the attach-time proof.
            Some(root) if root.canonical_path() == self.canonical_cwd => {
                vec![root.clone()]
            }
            Some(root) => {
                vec![
                    crate::daemon::agent_installation::AuthorizedWorkspaceRoot::capture(
                        &self.canonical_cwd,
                    )?,
                    root.clone(),
                ]
            }
            None => vec![
                crate::daemon::agent_installation::AuthorizedWorkspaceRoot::capture(
                    &self.canonical_cwd,
                )?,
            ],
        };
        Ok(Arc::new(
            crate::daemon::agent_installation::default_daemon_service_with_captured_workspace_roots(
                self.db.clone(),
                &self.paths,
                self.secret_vault.clone(),
                match providers {
                    Some(providers) => providers,
                    None => self
                        .config_source()
                        .load(&self.canonical_cwd)
                        .context("loading daemon provider configuration")?
                        .0,
                },
                authorized_roots,
            )?,
        ))
    }

    #[cfg(test)]
    pub(crate) fn with_credential_store_path(mut self, path: PathBuf) -> Self {
        self.credential_store_path = Some(path);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_host_capability_probes(
        mut self,
        probes: crate::host_capabilities::HostCapabilityProbeInputs,
    ) -> Self {
        self.host_capability_probes = probes;
        self
    }

    #[cfg(feature = "remote")]
    pub(crate) fn load_flycockpit_credential(
        &self,
    ) -> Result<Option<crate::auth::flycockpit::StoredFlycockpitCredential>> {
        let store = crate::credentials::CredentialStore::from_vault(self.secret_vault.clone())?;
        let Some(raw) = store.get(crate::auth::flycockpit::CREDENTIAL_KEY) else {
            return Ok(None);
        };
        serde_json::from_value(raw.clone())
            .context("parsing stored Flycockpit account credential")
            .map(Some)
    }

    #[cfg(all(test, feature = "remote"))]
    pub(crate) fn store_flycockpit_credential(
        &self,
        credential: &crate::auth::flycockpit::StoredFlycockpitCredential,
    ) -> Result<()> {
        crate::auth::flycockpit::store_credential_in_vault(self.secret_vault.clone(), credential)
    }

    #[cfg(test)]
    pub(crate) fn set_force_daemon_redaction_refresh_failure(&self, value: bool) {
        self.redaction_refresh_failure
            .store(value, Ordering::SeqCst);
    }

    pub(crate) fn redaction_publication_is_poisoned(&self) -> bool {
        self.redaction_publication_poisoned.load(Ordering::SeqCst)
    }

    pub(crate) fn poison_redaction_publication(&self, error: &anyhow::Error) {
        if !self
            .redaction_publication_poisoned
            .swap(true, Ordering::SeqCst)
        {
            tracing::error!(error = %error, "post-commit redaction publication failed; forcing daemon shutdown");
            self.shutdown.force();
        }
    }

    /// Publish the current vault-backed redaction table.  The test failpoint
    /// is kept at this boundary so local and remote owner mutations exercise
    /// identical publication-failure behavior.
    pub(crate) fn publish_owner_redaction_table(&self) -> Result<()> {
        #[cfg(test)]
        if self.redaction_refresh_failure.swap(false, Ordering::SeqCst) {
            anyhow::bail!("injected daemon redaction publication failure");
        }
        self.refresh_redaction_table()
    }

    /// Apply one owner-vault mutation and publish its redaction table as one
    /// logical operation. Publication lives outside SQLite, so a failure is
    /// compensated by restoring the exact prior item bytes (or its absence).
    pub(crate) fn mutate_owner_vault_item(
        &self,
        kind: cockpit_db::secret_vault::SecretVaultKind,
        item_id: &str,
        plaintext: Option<&[u8]>,
    ) -> Result<()> {
        let mutation = self
            .secret_vault
            .mutate_item(kind, item_id, plaintext)
            .map_err(|error| anyhow::anyhow!(error))?;
        if let Err(error) = self.publish_owner_redaction_table() {
            return self
                .restore_owner_vault_item(
                    kind,
                    item_id,
                    &mutation.after,
                    mutation.prior.row.as_ref(),
                )
                .map_err(|rollback| {
                    anyhow::anyhow!(
                        "redaction publication failed: {error}; vault rollback failed: {rollback}"
                    )
                })
                .and_then(|_| Err(error));
        }
        Ok(())
    }

    /// Delete an owner-vault item while coupling the account's org-sync
    /// disable transition to the same durable vault transaction. Redaction
    /// publication is process-local, so publication failure is compensated by
    /// restoring both the exact vault row and the prior sync enablement. A
    /// failed compensation poisons the daemon rather than serving with an
    /// unverifiable secret/redaction state.
    #[cfg(feature = "remote")]
    pub(crate) async fn mutate_owner_vault_item_with_org_sync_disabled(
        &self,
        kind: cockpit_db::secret_vault::SecretVaultKind,
        item_id: &str,
        server_url: &str,
    ) -> Result<()> {
        let vault = self.secret_vault.clone();
        let item_id = item_id.to_owned();
        let server_url = server_url.to_owned();
        let item_id_for_tx = item_id.clone();
        let server_url_for_tx = server_url.clone();
        let (mutation, prior_sync) = self
            .db
            .transaction(move |conn| {
                cockpit_db::secret_vault::ensure_inventory_generation_conn(conn)?;
                let mut stmt =
                    conn.prepare("SELECT org_id, enabled FROM sync_state WHERE server_url = ?1")?;
                let prior_sync = stmt
                    .query_map([&server_url_for_tx], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let mutation = vault
                    .mutate_item_on_conn(conn, kind, &item_id_for_tx, None)
                    .map_err(|error| anyhow::anyhow!(error))?;
                cockpit_db::Db::mark_org_sync_disabled_on_conn(
                    conn,
                    &server_url_for_tx,
                    chrono::Utc::now().timestamp_millis(),
                )?;
                Ok((mutation, prior_sync))
            })
            .await?;

        if let Err(publication_error) = self.publish_owner_redaction_table() {
            let rollback_vault = self.restore_owner_vault_item(
                kind,
                &item_id,
                &mutation.after,
                mutation.prior.row.as_ref(),
            );
            let db = self.db.clone();
            let restore_server_url = server_url.clone();
            let rollback_sync = db
                .transaction(move |conn| {
                    for (org_id, enabled) in prior_sync {
                        conn.execute(
                            "UPDATE sync_state SET enabled = ?3, updated_at_ms = ?4
                             WHERE server_url = ?1 AND org_id = ?2",
                            rusqlite::params![
                                restore_server_url,
                                org_id,
                                if enabled { 1_i64 } else { 0_i64 },
                                chrono::Utc::now().timestamp_millis(),
                            ],
                        )?;
                    }
                    Ok(())
                })
                .await;
            if let Err(error) = rollback_vault.and(rollback_sync) {
                self.poison_redaction_publication(&error);
                return Err(anyhow::anyhow!(
                    "redaction publication failed: {publication_error}; owner clear rollback failed: {error}"
                ));
            }
            return Err(publication_error);
        }
        Ok(())
    }

    fn restore_owner_vault_item(
        &self,
        kind: cockpit_db::secret_vault::SecretVaultKind,
        item_id: &str,
        expected: &crate::secure_key::SecretVaultItemSnapshot,
        prior: Option<&cockpit_db::secret_vault::SecretVaultItemRow>,
    ) -> Result<()> {
        if self
            .secret_vault
            .restore_item_if_unchanged(kind, item_id, expected, prior)
            .map_err(|error| anyhow::anyhow!(error))?
        {
            return Ok(());
        }
        // The failed publication left a row newer than the one this request
        // produced. Refresh once so the daemon does not retain a stale
        // redaction snapshot, then fail closed rather than clobbering it.
        let refresh_error = self.refresh_redaction_table().err();
        match refresh_error {
            Some(error) => anyhow::bail!(
                "owner vault item changed concurrently; refusing redaction rollback and refresh failed: {error}"
            ),
            None => {
                anyhow::bail!("owner vault item changed concurrently; refusing redaction rollback")
            }
        }
    }

    pub(crate) fn list_secret_inventory(
        &self,
        cursor: Option<&str>,
        requested_limit: Option<u16>,
    ) -> std::result::Result<proto::Response, proto::ErrorPayload> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Cursor {
            snapshot: String,
            kind: String,
            item_id: String,
        }

        fn digest(snapshot: &str) -> String {
            Sha256::digest(snapshot.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }

        let decode_cursor = |raw: &str| -> std::result::Result<Cursor, proto::ErrorPayload> {
            if raw.len() > proto::MAX_OWNER_INVENTORY_CURSOR_BYTES {
                return Err(proto::ErrorPayload {
                    code: proto::ErrorCode::BadRequest,
                    message: "secret inventory cursor exceeds maximum length".into(),
                });
            }
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(raw)
                .map_err(|_| proto::ErrorPayload {
                    code: proto::ErrorCode::BadRequest,
                    message: "invalid secret inventory cursor".into(),
                })?;
            let cursor: Cursor =
                serde_json::from_slice(&bytes).map_err(|_| proto::ErrorPayload {
                    code: proto::ErrorCode::BadRequest,
                    message: "invalid secret inventory cursor".into(),
                })?;
            if cursor.snapshot.len() != 64
                || cursor.item_id.is_empty()
                || cursor.item_id.len() > proto::MAX_OWNER_INVENTORY_ITEM_ID_BYTES
                || !matches!(
                    cursor.kind.as_str(),
                    "named_secret" | "credential_record" | "subscription_ack"
                )
            {
                return Err(proto::ErrorPayload {
                    code: proto::ErrorCode::BadRequest,
                    message: "invalid secret inventory cursor".into(),
                });
            }
            Ok(cursor)
        };

        let parsed = cursor.map(decode_cursor).transpose()?;
        let limit = requested_limit
            .map(usize::from)
            .unwrap_or(proto::MAX_OWNER_INVENTORY_PAGE_ENTRIES);
        if limit == 0 {
            return Err(proto::ErrorPayload {
                code: proto::ErrorCode::BadRequest,
                message: "secret inventory page limit must be positive".into(),
            });
        }
        let limit = limit.min(proto::MAX_OWNER_INVENTORY_PAGE_ENTRIES);
        let after = parsed
            .as_ref()
            .map(|cursor| (cursor.kind.as_str(), cursor.item_id.as_str()));
        let page = self
            .secret_vault
            .list_inventory_page(after, limit)
            .map_err(|error| proto::ErrorPayload {
                code: proto::ErrorCode::Internal,
                message: format!("listing secret inventory: {error}"),
            })?;
        if page.total_entries > proto::MAX_OWNER_INVENTORY_TOTAL_ENTRIES {
            return Err(proto::ErrorPayload {
                code: proto::ErrorCode::InventoryTooLarge,
                message: format!(
                    "secret inventory exceeds maximum of {} entries",
                    proto::MAX_OWNER_INVENTORY_TOTAL_ENTRIES
                ),
            });
        }
        let snapshot = digest(&page.snapshot);
        if parsed
            .as_ref()
            .is_some_and(|cursor| cursor.snapshot != snapshot)
        {
            return Err(proto::ErrorPayload {
                code: proto::ErrorCode::Conflict,
                message: "secret inventory changed; restart pagination".into(),
            });
        }
        let wire_kind = |kind: cockpit_db::secret_vault::SecretVaultKind| match kind {
            cockpit_db::secret_vault::SecretVaultKind::NamedSecret => {
                proto::SecretInventoryKind::NamedSecret
            }
            cockpit_db::secret_vault::SecretVaultKind::CredentialRecord => {
                proto::SecretInventoryKind::CredentialRecord
            }
            cockpit_db::secret_vault::SecretVaultKind::SubscriptionAck => {
                proto::SecretInventoryKind::SubscriptionAck
            }
            _ => unreachable!("inventory query returned a hidden vault kind"),
        };
        let mut count = page.items.len();
        loop {
            let has_more = page.has_more || count < page.items.len();
            let next_cursor = if has_more && count > 0 {
                let last = &page.items[count - 1];
                let raw = serde_json::to_vec(&Cursor {
                    snapshot: snapshot.clone(),
                    kind: last.kind.as_str().to_string(),
                    item_id: last.item_id.clone(),
                })
                .map_err(|error| proto::ErrorPayload {
                    code: proto::ErrorCode::Internal,
                    message: format!("serializing secret inventory cursor: {error}"),
                })?;
                let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
                if encoded.len() > proto::MAX_OWNER_INVENTORY_CURSOR_BYTES {
                    return Err(proto::ErrorPayload {
                        code: proto::ErrorCode::InventoryTooLarge,
                        message: "secret inventory cursor exceeds response bound".into(),
                    });
                }
                Some(encoded)
            } else {
                None
            };
            let response = proto::Response::SecretInventory {
                entries: page.items[..count]
                    .iter()
                    .map(|item| proto::SecretInventoryEntry {
                        name: item.item_id.clone(),
                        kind: wire_kind(item.kind),
                        configured: true,
                    })
                    .collect(),
                next_cursor,
            };
            let encoded = serde_json::to_vec(&response).map_err(|error| proto::ErrorPayload {
                code: proto::ErrorCode::Internal,
                message: format!("serializing secret inventory: {error}"),
            })?;
            if encoded.len() <= proto::MAX_OWNER_INVENTORY_PAGE_BYTES {
                return Ok(response);
            }
            if count <= 1 {
                return Err(proto::ErrorPayload {
                    code: proto::ErrorCode::InventoryTooLarge,
                    message: "a secret inventory entry exceeds the response byte cap".into(),
                });
            }
            count -= 1;
        }
    }

    #[cfg(feature = "remote")]
    pub(crate) fn flycockpit_account_view(&self) -> Result<Option<proto::FlycockpitAccountView>> {
        let Some(credential) = self.load_flycockpit_credential()? else {
            return Ok(None);
        };
        let fingerprint = Sha256::digest(credential.instance_token.as_bytes());
        let token_fingerprint = fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let relay_choice = credential.relay_choice.map(|mut relay| {
            relay.ws_url = proto::redact_url_for_owner_view(&relay.ws_url);
            relay
        });
        let view = proto::FlycockpitAccountView {
            server_url: credential.server_url,
            instance_id: credential.instance_id,
            account: credential.account,
            display_name: credential.display_name,
            relay_choice,
            token_fingerprint,
        };
        view.validate()?;
        Ok(Some(view))
    }

    /// The daemon's graceful-shutdown gate. New-user-work rejection and the
    /// single drain path both read it.
    pub fn shutdown_signal(&self) -> &crate::daemon::shutdown::ShutdownSignal {
        &self.shutdown
    }

    /// The stable, nonzero daemon boot UUID shared by the image-generation
    /// lifecycle worker (`worker_boot_id`) and job creation (`deadline_boot_id`).
    /// The chokepoint prompt calls `ImageGenerationJobService` with this so a job
    /// queued this boot is dispatchable by the worker this boot.
    pub fn image_generation_boot_id(&self) -> Uuid {
        self.image_generation_boot_id
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
        // Keep the redaction table current w.r.t. the vault, but rebuild it
        // ONLY when the durable vault inventory generation has advanced. A
        // rebuild walks the workspace (env/ssh secret scan) and spawns a git
        // worktree availability probe; doing that per event turns a bursty
        // broadcast (e.g. the in-process lag-marker path, which enqueues
        // thousands of events with no vault change) into an unbounded
        // fork/scan storm that starves the event loop. Gating on the
        // trigger-maintained generation still catches direct and cross-process
        // vault writes (a plain `refresh_redaction_table` on the owner-mutation
        // path stays authoritative), so no secret escapes redaction.
        let table = match self.secret_vault.current_inventory_generation() {
            Ok(generation)
                if generation
                    != self
                        .redaction_generation
                        .load(std::sync::atomic::Ordering::SeqCst) =>
            {
                match refresh_global_redaction_table(
                    &self.global_redaction,
                    &self.config_source,
                    &self.secret_vault,
                ) {
                    Ok(table) => {
                        self.redaction_generation
                            .store(generation, std::sync::atomic::Ordering::SeqCst);
                        table
                    }
                    Err(error) => {
                        tracing::error!(error = %error, "refreshing daemon redaction failed; retaining committed table");
                        current_redaction(&self.global_redaction)
                    }
                }
            }
            Ok(_) => current_redaction(&self.global_redaction),
            Err(error) => {
                tracing::error!(error = %error, "reading vault inventory generation failed; retaining committed redaction table");
                current_redaction(&self.global_redaction)
            }
        };
        send_event(&self.global_events, &table, event);
    }

    pub(crate) fn refresh_redaction_table(&self) -> Result<()> {
        refresh_global_redaction_table(
            &self.global_redaction,
            &self.config_source,
            &self.secret_vault,
        )
        .map(|_| ())
    }

    #[cfg(test)]
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

    /// Subscribe to connector wakeups. Credential store/clear requests use
    /// this to interrupt the connector's fallback polling sleep and any active
    /// relay socket so credential changes take effect immediately.
    #[cfg(feature = "remote")]
    pub fn connector_wake_rx(&self) -> watch::Receiver<u64> {
        self.connector_wake.subscribe()
    }

    #[cfg(feature = "remote")]
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

struct RegisteredInProcessContext {
    ctx: std::sync::Weak<DaemonContext>,
    endpoint: cockpit_client::InProcessEndpoint,
}

pub(crate) fn register_in_process_context(
    ctx: Arc<DaemonContext>,
) -> cockpit_client::InProcessEndpoint {
    // Endpoint service tasks are created on the daemon owner runtime. Callers
    // receive only the cloneable transport capability; reconnects never spawn
    // daemon work on a frontend runtime.
    let endpoint = in_process_endpoint(&ctx);
    let contexts = IN_PROCESS_CONTEXTS.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut contexts = contexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    contexts.insert(
        ctx.paths.socket.clone(),
        RegisteredInProcessContext {
            ctx: Arc::downgrade(&ctx),
            endpoint: endpoint.clone(),
        },
    );
    endpoint
}

pub(crate) fn in_process_endpoint(ctx: &Arc<DaemonContext>) -> cockpit_client::InProcessEndpoint {
    let (connections, mut requests) =
        mpsc::channel::<oneshot::Sender<Option<cockpit_client::InProcessConnection>>>(16);
    let (sensitive, mut sensitive_requests) =
        mpsc::channel::<cockpit_client::InProcessSensitiveRequest>(4);
    let weak = Arc::downgrade(ctx);
    tokio::spawn(async move {
        while let Some(reply) = requests.recv().await {
            if reply.is_closed() {
                continue;
            }
            let connection = weak.upgrade().map(spawn_in_process_client);
            let retired = connection.is_none();
            let _ = reply.send(connection);
            if retired {
                break;
            }
        }
    });
    let weak = Arc::downgrade(ctx);
    tokio::spawn(async move {
        while let Some(mut request) = sensitive_requests.recv().await {
            if request.reply.is_closed() {
                continue;
            }
            let Some(ctx) = weak.upgrade() else {
                break;
            };
            let response = match crate::daemon::leak_reveal_frame::decode_request(&request.payload)
            {
                Ok(decoded) => {
                    let consume = crate::daemon::leak_reveal::consume_leak_reveal(
                        &ctx,
                        decoded.capability_hex.as_str(),
                        chrono::Utc::now().timestamp_millis(),
                    );
                    let consumed = tokio::select! {
                        biased;
                        _ = request.reply.closed() => continue,
                        consumed = consume => consumed,
                    };
                    match consumed {
                        Ok(revealed) => {
                            crate::daemon::leak_reveal_frame::LeakRevealSocketResponse::Ok {
                                report_id: revealed.report_id,
                                generation: revealed.generation,
                                plaintext: revealed.plaintext,
                            }
                        }
                        Err(denied) => {
                            crate::daemon::leak_reveal_frame::LeakRevealSocketResponse::Denied(
                                denied,
                            )
                        }
                    }
                }
                Err(_) => crate::daemon::leak_reveal_frame::LeakRevealSocketResponse::Denied(
                    crate::daemon::leak_reveal::LeakRevealDenied::Unauthorized,
                ),
            };
            let encoded = zeroize::Zeroizing::new(
                crate::daemon::leak_reveal_frame::encode_response(&response),
            );
            let _ = request.reply.send(encoded);
        }
    });
    cockpit_client::InProcessEndpoint::new(connections, sensitive)
}

pub(crate) fn in_process_context(socket: &Path) -> Option<Arc<DaemonContext>> {
    let contexts = IN_PROCESS_CONTEXTS.get()?;
    let mut contexts = contexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let registered = contexts.get(socket)?;
    match registered.ctx.upgrade() {
        Some(ctx) => Some(ctx),
        None => {
            contexts.remove(socket);
            None
        }
    }
}

pub(crate) fn registered_in_process_endpoint(
    socket: &Path,
) -> Option<cockpit_client::InProcessEndpoint> {
    let contexts = IN_PROCESS_CONTEXTS.get()?;
    let mut contexts = contexts
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let registered = contexts.get(socket)?;
    if registered.ctx.upgrade().is_some() {
        Some(registered.endpoint.clone())
    } else {
        contexts.remove(socket);
        None
    }
}

/// Bootstrap the daemon: open the DB, build the lock manager, return
/// a ready-to-use context. Called from `daemon::run_foreground`.
pub async fn boot(
    paths: DaemonPaths,
    terminal_factory: crate::daemon::terminal::TerminalHostFactory,
) -> Result<DaemonContext> {
    let mut timer = crate::startup::PhaseTimer::start("daemon::boot");
    let db = Db::open_default().context("opening session DB")?;
    let ctx = boot_with_db(
        paths,
        db,
        &mut timer,
        terminal_factory,
        crate::daemon::config_source::ConfigSource::production(),
    )
    .await?;
    timer.done();
    Ok(ctx)
}

pub(crate) async fn boot_with_db(
    paths: DaemonPaths,
    db: Db,
    timer: &mut crate::startup::PhaseTimer,
    terminal_factory: crate::daemon::terminal::TerminalHostFactory,
    config_source: crate::daemon::config_source::ConfigSource,
) -> Result<DaemonContext> {
    #[cfg(not(test))]
    let mut containment_recovered = false;
    timer.phase("db_open_and_migrate");
    let locks = Arc::new(
        LockManager::from_db(db.clone())
            .await
            .context("loading lock state")?,
    );
    timer.phase("lock_manager");
    run_boot_housekeeping(&db).await;
    timer.phase("prune_and_sweep");
    let fenced_refreshes = db
        .reconcile_host_capability_refresh_execution_leases_at_boot(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            crate::agent_tree::system_now_unix_ms(),
        )
        .await
        .context("fencing prior-process host capability refresh executions")?;
    if fenced_refreshes > 0 {
        tracing::warn!(
            fenced_refreshes,
            "fenced global host capability refresh executions from a prior daemon process"
        );
    }
    anyhow::ensure!(
        !db.has_executing_host_capability_refresh_operations(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
        )
        .await
        .context("checking global host capability refresh execution fence")?,
        "host capability refresh execution fence remains live after boot reconciliation"
    );
    #[cfg_attr(test, allow(unused_mut))]
    let mut ctx = DaemonContext::new(db.clone(), locks, paths, terminal_factory, config_source);
    // A capability refresh receipt is daemon-global state, not a per-session
    // cache. Seed only from an already-published durable generation, then
    // replay the completed outbox below in order. Seeding from the newest
    // *unpublished* receipt would make an older outbox entry impossible to
    // publish and could overtake its generation at boot.
    match db
        .latest_published_host_capability_refresh_snapshot_receipt(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
        )
        .await
        .context("loading published host capability refresh receipt")?
    {
        Some(receipt) => {
            let snapshot: cockpit_proto::HostCapabilitySnapshot = serde_json::from_str(
                &receipt.result_snapshot_json,
            )
            .context("durable host capability refresh receipt is not a HostCapabilitySnapshot")?;
            anyhow::ensure!(
                snapshot.generation == receipt.generation,
                "durable host capability refresh receipt generation disagrees with its snapshot"
            );
            ctx.host_capabilities
                .observe_durable_generation(receipt.generation);
            ctx.host_capabilities
                .publish_committed(snapshot)
                .map_err(anyhow::Error::msg)
                .context("seeding host capability store from published refresh receipt")?;
        }
        None => {
            let high_water = db
                .host_capability_refresh_generation_high_water(
                    crate::agent_tree::daemon_host_capability_refresh_authority(),
                )
                .await
                .context("loading host capability refresh generation high-water")?;
            ctx.host_capabilities.observe_durable_generation(high_water);
        }
    };
    // Drain every completed global publication receipt before reserving the
    // boot generation. Each SQL read is keyset-bounded even for a large crash
    // backlog; publishing still advances strictly in durable generation
    // order, and the acknowledgement fences a later boot/probe.
    let mut outbox_after = None;
    loop {
        let page = db
            .completed_unpublished_host_capability_refresh_operations_page(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                outbox_after.clone(),
                crate::db::agent_tree_decisions::MAX_AGENT_TREE_PAGE_SIZE,
            )
            .await
            .context("loading host capability refresh boot outbox page")?;
        let next_cursor = page.next_cursor;
        for operation in page.entries {
            let raw = operation
                .result_snapshot_json
                .as_deref()
                .context("completed host capability refresh outbox row has no snapshot")?;
            let generation = operation
                .result_snapshot_generation
                .context("completed host capability refresh outbox row has no generation")?;
            let digest = operation
                .result_snapshot_digest
                .clone()
                .context("completed host capability refresh outbox row has no digest")?;
            let snapshot: cockpit_proto::HostCapabilitySnapshot = serde_json::from_str(raw)
                .context("completed host capability refresh outbox snapshot is malformed")?;
            anyhow::ensure!(
                snapshot.generation == generation,
                "completed host capability refresh outbox generation is inconsistent"
            );
            anyhow::ensure!(
                ctx.host_capabilities
                    .current()
                    .is_none_or(|current| current.generation <= generation),
                "host capability refresh boot outbox is behind an already-live completed generation"
            );
            ctx.host_capabilities
                .publish_committed(snapshot)
                .map_err(anyhow::Error::msg)
                .context("publishing completed host capability refresh boot outbox snapshot")?;
            db.mark_host_capability_refresh_published(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
                operation.session_id,
                operation.operation_id,
                generation,
                digest,
                crate::agent_tree::system_now_unix_ms(),
            )
            .await
            .context("acknowledging completed host capability refresh boot outbox")?;
        }
        let Some(cursor) = next_cursor else {
            break;
        };
        outbox_after = Some(cursor);
    }
    // A completed receipt which has not reached the live store is a hard
    // ordering fence: boot must replay that exact snapshot rather than probe
    // and expose a later generation first. Once that outbox is empty, the
    // normal boot probe may still refresh current host facts.
    let host_capability_boot_probe_blocked = !db
        .completed_unpublished_host_capability_refresh_operations_page(
            crate::agent_tree::daemon_host_capability_refresh_authority(),
            None,
            1,
        )
        .await
        .context("checking host capability refresh publication outbox")?
        .entries
        .is_empty();
    // The initial daemon probe shares the public snapshot generation
    // namespace with later approved refreshes. Reserve it durably rather than
    // leaving the first AgentTree refresh to collide with the live boot
    // snapshot at generation one. An acknowledged N therefore produces a
    // boot N+1 (and later approved work N+2), while an unpublished receipt
    // defers the probe until recovery makes its exact generation visible.
    let initial_host_capability_snapshot_generation = if !host_capability_boot_probe_blocked {
        let generation = db
            .reserve_host_capability_boot_snapshot_generation(
                crate::agent_tree::daemon_host_capability_refresh_authority(),
            )
            .await
            .context("reserving initial host capability snapshot generation")?;
        ctx.host_capabilities.observe_durable_generation(generation);
        Some(generation)
    } else {
        None
    };
    db.reconcile_delegation_sidecar_prepare_intents()
        .await
        .context("reconciling delegation sidecar prepare intents")?;
    db.reconcile_delegation_sidecar_cleanup_intents()
        .await
        .context("reconciling delegation sidecar cleanup intents")?;
    if let Some(storage) = &ctx.media_storage_recovery {
        storage
            .reconcile_abandoned_component_leases(chrono::Utc::now().timestamp_millis())
            .await
            .context("reconciling abandoned media component leases")?;
        storage
            .reconcile_media_uploads(chrono::Utc::now().timestamp_millis())
            .await
            .context("reconciling authenticated media uploads")?;
        storage
            .begin_due_retention(chrono::Utc::now().timestamp_millis())
            .await
            .context("starting due media retention")?;
        storage
            .reconcile_media_cleanup_intents(chrono::Utc::now().timestamp_millis())
            .await
            .context("reconciling media cleanup intents")?;
    }
    timer.phase("media_upload_reconcile");
    // Shared host-capability probes run once here. The TUI in-process doctor
    // snapshot is not the daemon's capability authority.
    //
    // `probe_platform_keyring()` is the only keyring construct on this boot
    // path. Vault start consumes that probe and must not construct the
    // platform store a second time. Snapshot publish waits until after vault
    // start so `secretStore` is filled from the authority row.
    #[cfg(not(test))]
    {
        let probes = crate::host_capabilities::collect_shared_host_probes(
            &ctx.host_capability_probes,
            false,
        )
        .await;
        let db_for_keys = db.clone();
        let keyring_probe = probes.keyring.clone();
        let (boot_tx, boot_rx) = tokio::sync::oneshot::channel();
        match std::thread::Builder::new()
            .name("cockpit-secure-key-boot".into())
            .spawn(move || {
                let external = crate::external_journal::keys::ExternalJournalSpoolReconciler::new(
                    db_for_keys.clone(),
                );
                let tool_media =
                    crate::secure_key::ToolMediaSubjectBindingDbProbe::new(db_for_keys.clone());
                let reconciler = std::sync::Arc::new(
                    crate::secure_key::CompositeConsumerReconciler::new(external, tool_media),
                );
                let result = crate::secure_key::SecureKeyActor::start_production_resolved(
                    db_for_keys,
                    reconciler,
                    &keyring_probe,
                    None,
                    crate::secure_key::SecretStoreInjected::default(),
                );
                let _ = boot_tx.send(result);
            }) {
            Ok(_handle) => match boot_rx.await {
                Ok(Ok(actor)) => {
                    ctx.attach_secure_key_actor(actor);
                    timer.phase("secure_key_actor");
                    if let Some(generation) = initial_host_capability_snapshot_generation {
                        let authority = db
                            .blocking_write_for_sync_maintenance(
                                crate::db::secret_vault::load_authority_conn,
                            )
                            .ok()
                            .flatten();
                        let secret_store = crate::secure_key::project_secret_store_snapshot(
                            authority.as_ref(),
                            &probes.keyring,
                        );
                        let snapshot = crate::host_capabilities::build_host_capability_snapshot(
                            generation,
                            &probes,
                            secret_store,
                        );
                        let _ = ctx.host_capabilities.publish(snapshot);
                    }
                    timer.phase("host_capabilities");
                }
                Ok(Err(error)) => {
                    if let Some(generation) = initial_host_capability_snapshot_generation {
                        let secret_store = match &error {
                            crate::secure_key::SecureKeyError::KekUnavailable {
                                reason,
                                fix_command,
                            } => cockpit_proto::SecretStoreSnapshot {
                                intent: cockpit_proto::SecretStoreIntent::Keyring,
                                effective_placement:
                                    cockpit_proto::SecretStorePlacement::Unavailable,
                                fail_closed_reason: Some(reason.clone()),
                                fix_command: fix_command.clone(),
                            },
                            _ => cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
                        };
                        let snapshot = crate::host_capabilities::build_host_capability_snapshot(
                            generation,
                            &probes,
                            secret_store,
                        );
                        let _ = ctx.host_capabilities.publish(snapshot);
                    }
                    timer.phase("host_capabilities");
                    return Err(anyhow::anyhow!("secure key vault: {error}"));
                }
                Err(_) => {
                    return Err(anyhow::anyhow!("secure key actor boot channel dropped"));
                }
            },
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "secure key actor boot thread spawn failed: {error}"
                ));
            }
        }
    }
    #[cfg(test)]
    {
        let _ = &db;
        if let Some(generation) = initial_host_capability_snapshot_generation {
            let probes = crate::host_capabilities::collect_shared_host_probes(
                &ctx.host_capability_probes,
                false,
            )
            .await;
            let snapshot = crate::host_capabilities::build_host_capability_snapshot(
                generation,
                &probes,
                cockpit_proto::SecretStoreSnapshot::unconfigured_placeholder(),
            );
            let _ = ctx.host_capabilities.publish(snapshot);
        }
        timer.phase("host_capabilities");
        timer.phase("secure_key_actor_skipped");
    }
    // Process containment actor: durable generation-bound descendant groups.
    // Under unit tests the actor is opt-in via `attach_process_containment_actor`
    // so paused-time daemon lifecycle tests are not blocked by a cross-runtime
    // barrier; production always installs and recovers.
    #[cfg(not(test))]
    {
        let adapter = crate::process_containment::default_host_adapter();
        let actor = crate::process_containment::ProcessContainmentActor::start(db.clone(), adapter);
        let handle = actor.handle();
        ctx.attach_process_containment_actor(actor);
        // Publish to the registry so every worker session installs the same
        // handle and spawns its lifecycle hooks under a proven containment lease.
        ctx.registry.set_process_containment(handle.clone());
        match handle.recover().await {
            Ok(outcomes) => {
                containment_recovered = true;
                tracing::info!(
                    recovered = outcomes.len(),
                    "process containment recovery finished"
                );
            }
            Err(error) => {
                tracing::warn!(error = %error, "process containment recovery failed");
            }
        }
        timer.phase("process_containment_actor");

        // Durable write-scope authority. One coordinator per daemon: `recover`
        // and the shutdown drain are daemon-global, so this cannot be per-child.
        //
        // The production filesystem backend is the direct workspace, which is
        // always Unsupported — so every strict writable delegation fails closed
        // here rather than in an ad-hoc gate. The lifecycle is nonetheless live:
        // recovery, session deletion, and shutdown all reconcile real rows.
        let coordinator = std::sync::Arc::new(crate::write_scope::WriteScopeCoordinator::new(
            db.clone(),
            std::sync::Arc::new(crate::write_scope::DirectWorkspaceBackend),
            std::sync::Arc::new(crate::write_scope::ProcessContainmentBarrier::new(
                handle.clone(),
            )),
            std::sync::Arc::new(crate::write_scope::NullEventSink),
            crate::write_scope::system_clock(),
        ));
        // Must run after containment recovery: reconciling a transfer consults
        // the containment oracle for ProvenEmpty.
        match coordinator.recover(None).await {
            Ok(outcomes) => {
                tracing::info!(recovered = outcomes.len(), "write scope recovery finished");
            }
            Err(error) => {
                tracing::warn!(error = %error, "write scope recovery failed");
            }
        }
        // Publish to the registry so every session worker installs the same
        // coordinator into its driver.
        ctx.registry.set_write_scope(coordinator.clone());
        ctx.write_scope = Some(coordinator);
        timer.phase("write_scope_coordinator");
    }
    #[cfg(test)]
    {
        let _ = db;
        timer.phase("process_containment_actor_skipped");
    }
    // External side-effect journal: recover the capsule spool and revalidate
    // recovery capacity BEFORE any external dispatch can be enabled. The
    // handle is published only once both succeed, so a consumer that cannot
    // see `ctx.external_journal` cannot start a non-idempotent external
    // action. Startup needs the secure-key handle for spool HMAC material.
    #[cfg(not(test))]
    {
        match &ctx.secure_key {
            Some(secure_key) => {
                let now_wall_ms = chrono::Utc::now().timestamp_millis();
                match crate::external_journal::ExternalJournal::start(
                    ctx.db.clone(),
                    secure_key,
                    now_wall_ms,
                )
                .await
                {
                    Ok((journal, report)) => {
                        tracing::info!(
                            scanned = report.scanned,
                            imported = report.imported,
                            quarantined = report.quarantined,
                            converted = report.converted,
                            released_without_medium = report.released_without_medium,
                            "external side-effect journal recovery finished"
                        );
                        let journal = std::sync::Arc::new(journal);
                        ctx.registry.set_external_journal(journal.clone());
                        ctx.external_journal = Some(journal);
                        timer.phase("external_journal");
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "external side-effect journal startup failed; \
                             non-idempotent external actions stay disabled"
                        );
                        timer.phase("external_journal_blocked");
                    }
                }
            }
            None => {
                tracing::warn!(
                    "native secure keys unavailable; external side-effect journal \
                     stays disabled and non-idempotent external actions are refused"
                );
                timer.phase("external_journal_skipped");
            }
        }
    }
    #[cfg(test)]
    {
        timer.phase("external_journal_skipped");
    }
    let recovery_wall_ms = chrono::Utc::now()
        .timestamp_millis()
        .try_into()
        .unwrap_or(0);
    #[cfg(not(test))]
    if containment_recovered {
        // The only production local media owner is currently the attachment
        // path, whose collected and decoded bytes are process memory. Reaped
        // daemon containment is therefore positive cleanup evidence for every
        // local reservation this binary can create. This contract must grow an
        // owner-specific deleter before any file-backed producer is added.
        match ctx
            .media_ledger
            .recover_after_restart(recovery_wall_ms, &RestartEphemeralMediaCleanup)
            .await
        {
            Ok(recovered) => {
                tracing::info!(recovered, "media reservation restart recovery finished");
                timer.phase("media_reservation_recovered");
            }
            Err(error) => {
                tracing::warn!(%error, "media reservation restart recovery failed");
                timer.phase("media_reservation_recovery_blocked");
            }
        }
    }
    if let Err(error) = ctx
        .media_ledger
        .recover_ephemeral_attachment_uploads(recovery_wall_ms)
        .await
    {
        tracing::warn!(%error, "ephemeral attachment reservation recovery failed");
    }
    if let Err(error) = ctx
        .media_ledger
        .reconcile_terminal_downstream_ownership(recovery_wall_ms)
        .await
    {
        tracing::warn!(%error, "terminal downstream media ownership reconciliation failed");
    }
    let recovery_complete = ctx.media_ledger.recovery_complete().await.unwrap_or(false);
    ctx.media_admission_open
        .store(recovery_complete, std::sync::atomic::Ordering::Release);
    if recovery_complete {
        timer.phase("media_reservation_admission_open");
    } else {
        tracing::warn!("media admission is closed until durable reservations are recovered");
        timer.phase("media_reservation_admission_blocked");
    }
    if let Some(handle) = &ctx.scheduler
        && let Err(error) = crate::skills::curator::register_scheduler(handle, ctx.db.clone()).await
    {
        tracing::warn!(error = %error, "skill curator scheduler registration failed");
    }
    // Resolve command-backed named secrets referenced by configured provider
    // headers into the daemon cache. Failures land as `Failed` (never fail
    // boot); the first outbound request then sees the cached status, not a sync
    // exec.
    ctx.resolve_startup_command_secrets().await;
    timer.phase("command_secret_startup_resolve");
    Ok(ctx)
}

const TERMINAL_REAPER_POLL: Duration = Duration::from_secs(30);

#[cfg(not(test))]
struct RestartEphemeralMediaCleanup;

#[cfg(not(test))]
impl crate::media_reservation::LocalExpiryCleanup for RestartEphemeralMediaCleanup {
    fn kill_reap_and_cleanup(&self, reservation_id: &str) -> anyhow::Result<String> {
        Ok(format!(
            "daemon-restart-ephemeral-media-destroyed:{reservation_id}"
        ))
    }
}

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

async fn run_boot_housekeeping(db: &Db) {
    // Drop autocomplete-tally rows that have aged out of the 30-day
    // window. Best-effort — a prune failure shouldn't block boot.
    let before = chrono::Utc::now().timestamp() - crate::db::usage_events::USAGE_WINDOW_SECS;
    if let Err(e) = db.blocking_write_for_sync_maintenance(move |conn| {
        crate::db::usage_events::prune_usage_events_conn(conn, before)
    }) {
        tracing::warn!(error = %e, "pruning usage_events on boot failed");
    }
    // SIGKILL backstop for `/side`: a side conversation whose owning process
    // died uncatchably can orphan an ephemeral session row. Sweep them on
    // boot so ephemeral sessions never accumulate. Best-effort.
    // The async accessor deletes each session in its own transaction, so the
    // external side-effect tombstone and the deletion commit together. The
    // former blocking duplicate here issued a raw `DELETE` loop under
    // `blocking_write_for_sync_maintenance`, where every statement
    // autocommitted separately.
    match db.sweep_ephemeral_sessions().await {
        Ok(n) if n > 0 => tracing::info!(count = n, "swept orphaned ephemeral sessions on boot"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "sweeping ephemeral sessions on boot failed"),
    }
    match db.sweep_empty_display_sessions().await {
        Ok(n) if n > 0 => tracing::info!(count = n, "swept empty display-only sessions on boot"),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "sweeping empty display sessions on boot failed"),
    }
    run_retention_pass(
        db.clone(),
        retention_config(),
        chrono::Utc::now().timestamp(),
    )
    .await;
    // Durable task executors are recovered by the owning session worker. A
    // daemon restart is not evidence that a running child was lost; marking
    // every live row failed here would discard its exact lifecycle claim,
    // pending decision, and approved host-effect receipt before reattachment
    // gets a chance to run.
}

/// Complete fail-closed local authority recovery before either daemon socket
/// is bound. A published socket promises an immediately responsive protocol;
/// recovery therefore belongs to boot, never the accept loop.
#[cfg(unix)]
pub async fn recover_before_socket_publish(ctx: &Arc<DaemonContext>) -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    // Every file-backed recovery family shares one bounded startup deadline.
    // Target guards themselves live only inside blocking closures, so no
    // synchronous filesystem lock can cross an async DB/network suspension.
    let config_publication =
        crate::daemon::config_publication_recovery::PreSocketConfigPublication::new();
    dispatch::recover_all_provider_config_journals(ctx, config_publication)
        .await
        .map_err(|error| anyhow::anyhow!(error.message))
        .context("startup provider-config journal recovery failed")?;
    dispatch::recover_all_mcp_config_journals(ctx, config_publication)
        .await
        .map_err(|error| anyhow::anyhow!(error.message))
        .context("startup MCP-config journal recovery failed")?;
    crate::daemon::fs_api::recover_extended_config_patch_journals(ctx, config_publication)
        .await
        .map_err(|error| anyhow::anyhow!(error.message))
        .context("startup typed-settings journal recovery failed")?;
    let recovered_image_config =
        image_control_mutations::recover_image_config_mutation_journals(ctx, config_publication)
            .await
            .map_err(|error| anyhow::anyhow!(error.message))
            .context("startup image-config mutation journal recovery failed")?;
    if recovered_image_config > 0 {
        tracing::info!(
            count = recovered_image_config,
            "reconciled committed image configuration before socket publication"
        );
    }
    crate::daemon::agent_management::recover_known_workspace_resets(ctx, config_publication)
        .await
        .map_err(|error| anyhow::anyhow!(error.message))
        .context("startup agent reset journal recovery failed")?;
    let recovered_agent_mutations =
        crate::daemon::agent_management::recover_agent_mutation_journals(ctx, config_publication)
            .await
            .map_err(|error| anyhow::anyhow!(error.message))
            .context("startup agent-mutation journal recovery failed")?;
    if recovered_agent_mutations > 0 {
        tracing::info!(
            count = recovered_agent_mutations,
            "reconciled committed agent mutations before socket publication"
        );
    }
    dispatch::recover_committed_oauth_settlements(ctx)
        .await
        .context("reconciling committed OAuth authority operations")?;
    crate::assistants::recover_definition_journals(&ctx.db)
        .await
        .context("startup assistant-definition journal recovery failed")?;
    let recovered_assistants = dispatch::recover_assistant_mutation_journals(ctx)
        .await
        .map_err(|error| anyhow::anyhow!(error.message))
        .context("startup assistant-mutation receipt recovery failed")?;
    if recovered_assistants > 0 {
        tracing::info!(
            count = recovered_assistants,
            "reconciled committed assistant mutations before socket publication"
        );
    }
    let interrupted = ctx
        .db
        .settle_interrupted_local_operations()
        .await
        .context("settling interrupted local authority operations")?;
    if interrupted > 0 {
        tracing::warn!(
            count = interrupted,
            "settled interrupted local operations without re-execution"
        );
    }
    crate::daemon::agent_management::recover_editor_leases_before_publish(ctx, config_publication)
        .await
        .map_err(|error| anyhow::anyhow!(error.message))
        .context("startup editor completion recovery failed")?;
    crate::daemon::agent_management::maintain_editor_leases(ctx)
        .await
        .map_err(|error| anyhow::anyhow!(error.message))
        .context("startup editor lease recovery failed")?;
    let recovered =
        crate::daemon::effective_default_recovery::recover_effective_default_journals_before_socket(
            &ctx.db,
            &cwd,
            config_publication,
        )
    .await
    .context("startup effective-default journal recovery failed")?;
    crate::daemon::effective_default_recovery::deliver_recovered_terminals(ctx, recovered)
        .await
        .context("startup recovered effective-default receipt delivery failed")?;
    Ok(())
}

/// Bind the Unix socket and run the accept loop until the daemon's
/// graceful-shutdown gate leaves `Running`. Each accepted connection spawns
/// a detached client task. Breaking the loop hands control back to
/// [`crate::daemon::run_foreground_inner`], which drains the workers.
#[cfg(unix)]
pub async fn run_accept_loop(ctx: Arc<DaemonContext>, listener: UnixListener) -> Result<()> {
    // Wiring invariant (debug/CI): the transactional ledger-site registry must
    // exactly cover the remotely-admissible transactional_mutation commands.
    #[cfg(feature = "remote")]
    dispatch::debug_assert_ledger_site_registry_consistent();
    let mut shutdown = ctx.shutdown.subscribe();
    let retention_cfg = retention_config();
    let mut retention_interval = tokio::time::interval(std::time::Duration::from_secs(
        (retention_cfg.sweep_interval_hours.max(1) as u64) * 60 * 60,
    ));
    retention_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    retention_interval.tick().await;
    let mut editor_maintenance_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    editor_maintenance_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    editor_maintenance_interval.tick().await;
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
            _ = editor_maintenance_interval.tick() => {
                if let Err(error) = crate::daemon::agent_management::maintain_editor_leases(&ctx).await {
                    tracing::warn!(message = %error.message, "editor lease maintenance failed");
                }
                if let Err(error) = dispatch::maintain_durable_oauth_flows(&ctx).await {
                    tracing::warn!(message = %error.message, "OAuth flow maintenance failed");
                }
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
    if outcome.sessions_expired > 0
        || outcome.payload_rows_deleted > 0
        || outcome.local_authority_rows_purged > 0
        || outcome.vacuumed
    {
        tracing::info!(
            sessions_expired = outcome.sessions_expired,
            session_cascade_rows_deleted = outcome.session_cascade_rows_deleted,
            payload_rows_deleted = outcome.payload_rows_deleted,
            transcript_rows_deleted = outcome.transcript_rows_deleted,
            raw_wire_rows_deleted_or_redacted = outcome.raw_wire_rows_deleted_or_redacted,
            terminal_evidence_rows_deleted = outcome.terminal_evidence_rows_deleted,
            local_authority_rows_purged = outcome.local_authority_rows_purged,
            vacuumed = outcome.vacuumed,
            "session payload retention pass completed"
        );
    }
}

async fn run_retention_pass(db: Db, cfg: RetentionConfig, now_secs: i64) {
    match db.run_retention_pass(&cfg, now_secs).await {
        Ok(outcome) => log_retention_outcome(outcome),
        Err(error) => tracing::warn!(error = %error, "session payload retention pass failed"),
    }
}

#[cfg(any(unix, test))]
async fn run_retention_tick(ctx: Arc<DaemonContext>, cfg: RetentionConfig) {
    run_retention_tick_db(ctx.db.clone(), cfg).await;
    if let Err(error) = crate::daemon::agent_management::maintain_editor_leases(&ctx).await {
        tracing::warn!(message = %error.message, "editor lease maintenance failed");
    }
}

#[cfg(any(unix, test))]
async fn run_retention_tick_db(db: Db, cfg: RetentionConfig) {
    let now_secs = chrono::Utc::now().timestamp();
    run_retention_pass(db, cfg, now_secs).await;
}

/// Same-uid peer check used by the control-socket accept loop **and** the
/// dedicated leak-reveal socket accept loop — one shared policy, never a
/// hand-rolled second `SO_PEERCRED`/`getpeereid` path. Elevated to `pub(crate)`
/// so the reveal accept loop (a sibling `daemon` module) reuses it.
#[cfg(unix)]
pub(crate) fn validate_peer_owner(stream: &UnixStream) -> Result<()> {
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

struct MutableClientState {
    principal: ClientPrincipal,
    terminal_context: crate::daemon::terminal::AuthenticatedTerminalContext,
    attached: Option<AttachedSession>,
    pending_replay: Vec<proto::Event>,
    pending_uploads: HashMap<Uuid, PendingAttachmentUpload>,
    #[cfg(test)]
    ready_attachments: HashMap<Uuid, ReadyAttachment>,
    upload_accounting: Arc<StdMutex<UploadAccounting>>,
    upload_limits: AttachmentUploadLimits,
    terminal_views: HashMap<Uuid, proto::terminal::TerminalBinding>,
    terminal_host: crate::daemon::terminal::TerminalHostHandle,
    /// Negotiated protocol version for this connection, updated from each
    /// inbound envelope's `v`. v10-only semantic changes (e.g. active-session
    /// rejection in DeleteSession) are gated on this so a v9 client retains
    /// its frozen behavior.
    negotiated_protocol_version: u32,
}

/// Immutable client-state view published by the serialized executor.
///
/// Future concurrent handlers receive an `Arc` clone of this snapshot as it
/// existed when their request was dequeued. If attach/detach happens later,
/// the older snapshot remains valid for authorization and response scrubbing
/// of that already-received request.
#[derive(Clone)]
pub(super) struct SharedClientState {
    principal: ClientPrincipal,
    capability_owner: String,
    #[allow(dead_code)]
    upload_accounting: Arc<StdMutex<UploadAccounting>>,
    #[allow(dead_code)]
    terminal_host: crate::daemon::terminal::TerminalHostHandle,
    terminal_views: HashMap<Uuid, proto::terminal::TerminalBinding>,
    attached: Option<SharedAttachedSession>,
}

#[derive(Clone)]
pub(super) struct SharedAttachedSession {
    session_id: Uuid,
    project_root: PathBuf,
    workspace_identity: Option<crate::daemon::agent_installation::AuthorizedWorkspaceRoot>,
    /// A concurrent request still has to enter the one attached session worker
    /// for durable decision ownership. Keeping this immutable handle in the
    /// per-request snapshot lets a long-lived operation wait outside the
    /// client's serialized decoder without borrowing mutable client state.
    handle: SessionWorkerHandle,
    redaction_table: Arc<RedactionTable>,
    #[allow(dead_code)] // retained for attach-time toolbox identity snapshots
    active_tool_names: Vec<String>,
}

impl SharedAttachedSession {
    pub(super) fn session_id(&self) -> Uuid {
        self.session_id
    }

    pub(super) fn redaction_table(&self) -> Arc<RedactionTable> {
        self.redaction_table.clone()
    }
}

struct ConcurrentRequestRuntime {
    permits: Arc<Semaphore>,
    tasks: JoinSet<()>,
}

impl ConcurrentRequestRuntime {
    fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENT_REQUESTS)),
            tasks: JoinSet::new(),
        }
    }

    #[cfg(test)]
    fn with_permits_for_test(permits: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(permits)),
            tasks: JoinSet::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    async fn join_next(&mut self) -> Option<std::result::Result<(), tokio::task::JoinError>> {
        self.tasks.join_next().await
    }
}

impl MutableClientState {
    fn detached_with_principal(
        upload_accounting: Arc<StdMutex<UploadAccounting>>,
        principal: ClientPrincipal,
        terminal_host: crate::daemon::terminal::TerminalHostHandle,
        client_instance_id: Uuid,
        connection_epoch: u64,
    ) -> Self {
        let principal_id = principal.tag().unwrap_or_else(|| "local-owner".to_string());
        Self {
            principal,
            terminal_context: crate::daemon::terminal::AuthenticatedTerminalContext {
                principal_id,
                client_instance_id,
                connection_epoch,
            },
            attached: None,
            pending_replay: Vec::new(),
            pending_uploads: HashMap::new(),
            #[cfg(test)]
            ready_attachments: HashMap::new(),
            upload_accounting,
            upload_limits: AttachmentUploadLimits,
            terminal_views: HashMap::new(),
            terminal_host,
            negotiated_protocol_version: proto::PROTOCOL_VERSION,
        }
    }

    #[cfg(test)]
    fn detached_for_test() -> Self {
        Self::detached_with_principal(
            Arc::new(StdMutex::new(UploadAccounting::default())),
            ClientPrincipal::owner(),
            test_terminal_host(),
            Uuid::new_v4(),
            next_terminal_connection_epoch(),
        )
    }

    /// Update the negotiated protocol version from an inbound envelope. The
    /// envelope version is the min(client, daemon) negotiated value, so this
    /// is the authoritative per-connection version for semantic gates.
    fn update_negotiated_protocol_version(&mut self, v: u32) {
        self.negotiated_protocol_version = v;
    }

    /// The negotiated protocol version for this connection. v10-only
    /// semantic changes gate on this so v9 clients keep frozen behavior.
    fn negotiated_protocol_version(&self) -> u32 {
        self.negotiated_protocol_version
    }

    #[cfg(test)]
    fn detached_for_test_with_protocol_version(version: u32) -> Self {
        let mut state = Self::detached_for_test();
        state.negotiated_protocol_version = version;
        state
    }

    fn shared_snapshot(&self) -> Arc<SharedClientState> {
        Arc::new(SharedClientState {
            principal: self.principal.clone(),
            // Capabilities survive the settings client's short transport
            // reconnects. Root, layer, identity and revision remain bound in
            // the capability itself; the owner is the stable authenticated
            // principal used by the serialized Apply path.
            capability_owner: run_invocation::principal_digest(&self.principal),
            upload_accounting: self.upload_accounting.clone(),
            terminal_host: self.terminal_host.clone(),
            terminal_views: self.terminal_views.clone(),
            attached: self.attached.as_ref().map(|att| SharedAttachedSession {
                session_id: att.handle.session_id,
                project_root: att.handle.project_root.clone(),
                workspace_identity: att.workspace_identity.clone(),
                handle: att.handle.clone(),
                redaction_table: att.handle.redaction_table(),
                active_tool_names: att.handle.active_tool_names(),
            }),
        })
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

impl Drop for MutableClientState {
    fn drop(&mut self) {
        release_uploads(
            &self.upload_accounting,
            self.pending_uploads.keys().copied(),
        );
        for (terminal_id, binding) in self.terminal_views.drain() {
            self.terminal_host.release_viewer(terminal_id, binding);
        }
    }
}

const MIN_ATTACHMENT_UPLOAD_BYTES: usize = 64 * 1024;
static NEXT_TERMINAL_CONNECTION_EPOCH: AtomicU64 = AtomicU64::new(1);

fn next_terminal_connection_epoch() -> u64 {
    NEXT_TERMINAL_CONNECTION_EPOCH.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AttachmentUploadLimits;

impl AttachmentUploadLimits {
    fn from_config(config: DaemonUploadLimitsConfig) -> Self {
        let (limits, warning) = Self::from_config_with_warning(config);
        if let Some(warning) = warning {
            tracing::warn!(%warning, "daemon upload limit adjusted");
        }
        limits
    }

    fn from_config_with_warning(config: DaemonUploadLimitsConfig) -> (Self, Option<String>) {
        let (_, warning) = normalize_per_upload_bytes(config.per_upload_bytes);
        (Self, warning)
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
    /// Track which in-memory upload owns bytes. Durable evaluated ledger plans
    /// are the sole capacity/admission authority.
    fn track_pending(&mut self, upload_id: Uuid, byte_len: usize) {
        self.pending.insert(upload_id, byte_len);
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
    media_reservation: Option<crate::media_reservation::ReservationReceipt>,
    media_resources_policy: Option<Box<crate::config::media_budget::MediaResourcePolicy>>,
    session_id: Option<Uuid>,
    byte_len: usize,
    sha256: String,
    purpose: proto::AttachmentPurpose,
    bytes: Vec<u8>,
    created_at: Instant,
}

#[cfg(test)]
#[derive(Debug)]
struct ReadyAttachment {
    session_id: Uuid,
    bytes: Vec<u8>,
    purpose: proto::AttachmentPurpose,
}

struct AttachedSession {
    handle: SessionWorkerHandle,
    /// Captured at attach before this connection can issue setup reads. The
    /// setup projection verifies this stable directory identity rather than
    /// authorizing a later object that happens to reuse the same pathname.
    workspace_identity: Option<crate::daemon::agent_installation::AuthorizedWorkspaceRoot>,
    /// Held for the lifetime of the attachment when this client is
    /// interactive (can answer interrupts). Dropping it on detach /
    /// re-attach / disconnect decrements the worker's interactive-client
    /// count so the loop guard reverts to headless behavior. `None` for a
    /// non-interactive attach (e.g. `cockpit run`'s event pump).
    _interactive_guard: Option<crate::daemon::session_worker::InteractiveClientGuard>,
}

#[derive(Default)]
pub(super) struct ClientRequestEffects {
    session_event_rx: Option<EventReceiver>,
    shutdown_after_response: bool,
}

pub(crate) fn spawn_in_process_client(
    ctx: Arc<DaemonContext>,
) -> cockpit_client::InProcessConnection {
    let (request_tx, request_rx) = mpsc::channel(IN_PROCESS_REQUEST_QUEUE);
    let (event_tx, event_rx) = mpsc::channel(IN_PROCESS_EVENT_QUEUE);
    tokio::spawn(run_in_process_client(ctx, request_rx, event_tx));
    cockpit_client::InProcessConnection {
        requests: request_tx,
        events: event_rx,
    }
}

async fn run_in_process_client(
    ctx: Arc<DaemonContext>,
    mut request_rx: mpsc::Receiver<cockpit_client::InProcessRequest>,
    event_tx: mpsc::Sender<proto::Event>,
) {
    let _client_guard = ctx.track_client();
    let client_instance_id = Uuid::new_v4();
    let mut state = MutableClientState::detached_with_principal(
        ctx.upload_accounting.clone(),
        ClientPrincipal::owner(),
        ctx.terminal_host.clone(),
        client_instance_id,
        next_terminal_connection_epoch(),
    );
    let mut shared = state.shared_snapshot();
    let mut global_rx = ctx.subscribe_global();
    let mut session_event_rx: Option<EventReceiver> = None;
    let concurrent_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CLIENT_REQUESTS));
    let mut concurrent_tasks = JoinSet::new();
    let mut pending_lag = PendingEventLag::default();

    let client_ready = match event_tx.try_send(ctx.caffeinate_state_event()) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
            false
        }
    };

    if client_ready {
        'client: loop {
            let event_branch = async {
                match session_event_rx.as_mut() {
                    Some(rx) => Some(rx.recv().await),
                    None => std::future::pending().await,
                }
            };

            tokio::select! {
                biased;
                permit = event_tx.reserve(), if pending_lag.has_dropped() => {
                    match permit {
                        Ok(permit) => {
                            if let Some(event) = pending_lag.take_event() {
                                permit.send(event);
                            }
                        }
                        Err(_) => break 'client,
                    }
                }
                Some(joined) = concurrent_tasks.join_next(), if !concurrent_tasks.is_empty() => {
                    if let Err(error) = joined {
                        tracing::warn!(%error, "in-process concurrent request task failed");
                    }
                }
                global = global_rx.recv() => {
                    match global {
                        Ok(envelope) => {
                            if !try_send_in_process_event(&event_tx, envelope.event, None, &mut pending_lag) {
                                break 'client;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!(missed = n, "in-process client global event stream lagged");
                            pending_lag.record_many(n, None);
                            if !try_send_in_process_event(&event_tx, ctx.caffeinate_state_event(), None, &mut pending_lag) {
                                break 'client;
                            }
                            if let Some(event) = ctx.drain_state_event()
                                && !try_send_in_process_event(&event_tx, event, None, &mut pending_lag)
                            {
                                break 'client;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {}
                    }
                }
                event = event_branch => {
                    match event {
                        Some(Ok(envelope)) => {
                            let session_id = state
                                .attached
                                .as_ref()
                                .map(|attached| attached.handle.session_id);
                            if !try_send_in_process_event(
                                &event_tx,
                                envelope.event,
                                session_id,
                                &mut pending_lag,
                            ) {
                                break 'client;
                            }
                        }
                        Some(Err(broadcast::error::RecvError::Lagged(n))) => {
                            tracing::warn!(missed = n, "in-process client event stream lagged; reattach to resync");
                            let session_id = state
                                .attached
                                .as_ref()
                                .map(|attached| attached.handle.session_id);
                            pending_lag.record_many(n, session_id);
                        }
                        Some(Err(broadcast::error::RecvError::Closed)) => {
                            state.attached = None;
                            shared = state.shared_snapshot();
                            session_event_rx = None;
                        }
                        None => unreachable!("event_branch is pending when not attached"),
                    }
                }
                cmd = request_rx.recv() => {
                    let Some(cockpit_client::InProcessRequest { request, reply }) = cmd else {
                        break 'client;
                    };
                    if principal::request_ordering(&request) == principal::RequestOrdering::Concurrent {
                        let Ok(permit) = concurrent_permits.clone().acquire_owned().await else {
                            break 'client;
                        };
                        let shared = shared.clone();
                        let ctx = ctx.clone();
                        concurrent_tasks.spawn(async move {
                            let _permit = permit;
                            let result = run_concurrent_request_catching_panic(request, shared, ctx).await;
                            let _ = reply.send(result);
                        });
                        continue;
                    }
                    let is_attach = matches!(&request, Request::Attach { .. });
                    let mut effects = ClientRequestEffects::default();
                    let result = dispatch::handle_serialized_request(
                        request,
                        &mut state,
                        &shared,
                        &ctx,
                        &mut effects,
                    )
                    .await;
                    let attached = matches!(&result, Ok(Response::Attached { .. }));
                    if (is_attach && attached) || state.attached.is_none() {
                        shared = state.shared_snapshot();
                    }
                    let _ = reply.send(result);
                    if is_attach && attached {
                        let session_id = state
                            .attached
                            .as_ref()
                            .map(|attached| attached.handle.session_id);
                        for event in std::mem::take(&mut state.pending_replay) {
                            if !try_send_in_process_event(&event_tx, event, session_id, &mut pending_lag) {
                                break 'client;
                            }
                        }
                        if let Some(event) = ctx.drain_state_event()
                            && !try_send_in_process_event(&event_tx, event, None, &mut pending_lag)
                        {
                            break 'client;
                        }
                    }
                    if let Some(rx) = effects.session_event_rx.take() {
                        session_event_rx = Some(rx);
                    } else if state.attached.is_none() {
                        session_event_rx = None;
                    }
                }
            }
        }
    }
    // Concurrent dispatch owns the only tasks that can mint sealed
    // capabilities. Abort and join them before cancellation so teardown is a
    // hard insertion fence, matching the socket transport.
    concurrent_tasks.abort_all();
    while concurrent_tasks.join_next().await.is_some() {}
    if let Err(error) =
        attachments::drain_client_attachment_ownership(&mut state, &ctx, "disconnect").await
    {
        tracing::warn!(message=%error.message,"in-process attachment ownership drain failed; durable charges remain for startup recovery");
    }
    let cancelled_capabilities = ctx
        .sealed_owner_capabilities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .cancel_for_session(client_instance_id);
    if cancelled_capabilities > 0 {
        tracing::debug!(
            client_instance_id = %client_instance_id,
            cancelled_capabilities,
            "cancelled sealed capabilities at in-process client teardown"
        );
    }
}

#[derive(Default)]
struct PendingEventLag {
    dropped: u64,
    session_id: Option<Uuid>,
}

impl PendingEventLag {
    fn has_dropped(&self) -> bool {
        self.dropped > 0
    }

    fn record_drop(&mut self, session_id: Option<Uuid>) {
        self.record_many(1, session_id);
    }

    fn record_many(&mut self, dropped: u64, session_id: Option<Uuid>) {
        if dropped == 0 {
            return;
        }
        if self.dropped == 0 {
            self.session_id = session_id;
        } else if self.session_id != session_id {
            self.session_id = None;
        }
        self.dropped = self.dropped.saturating_add(dropped);
    }

    fn take_event(&mut self) -> Option<proto::Event> {
        if self.dropped == 0 {
            return None;
        }
        let event = proto::Event::EventStreamLagged {
            session_id: self.session_id,
            dropped: self.dropped,
        };
        self.dropped = 0;
        self.session_id = None;
        Some(event)
    }
}

fn try_send_in_process_event(
    event_tx: &mpsc::Sender<proto::Event>,
    event: proto::Event,
    session_id: Option<Uuid>,
    pending_lag: &mut PendingEventLag,
) -> bool {
    match event_tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(event)) => {
            tracing::warn!(?event, "in-process client event queue full; dropping event");
            pending_lag.record_drop(session_id);
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

#[cfg(unix)]
async fn handle_client(stream: UnixStream, ctx: Arc<DaemonContext>) -> Result<()> {
    handle_client_transport(stream, ctx).await
}

#[cfg(feature = "remote")]
pub(crate) async fn handle_relay_channel_as_with_instance<S>(
    stream: S,
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
    client_instance_id: Uuid,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_client_transport_as(stream, ctx, principal, client_instance_id).await
}

#[cfg(any(unix, test))]
async fn handle_client_transport<S>(stream: S, ctx: Arc<DaemonContext>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_client_transport_as(stream, ctx, ClientPrincipal::owner(), Uuid::new_v4()).await
}

async fn handle_client_transport_as<S>(
    stream: S,
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
    client_instance_id: Uuid,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Count this client for the lifetime of the task. The guard
    // decrements on every return below (Layer C presence tracking).
    let _client_guard = ctx.track_client();
    let proto = ProtoStream::new(stream);
    let (reader, writer) = proto.into_split();
    let (writer_tx, writer_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (executor_tx, executor_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);
    let (event_cmd_tx, event_cmd_rx) = mpsc::channel(CLIENT_IO_CHANNEL_CAPACITY);

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
                .await
                .map(|r| r.len())
                .unwrap_or(0) as u32,
            database_path: ctx
                .db
                .path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<in-memory>".to_string()),
            schema_version: ctx.db.schema_version().await.unwrap_or(0),
        },
    );
    if !send_writer_envelope(&writer_tx, hello).await {
        return Ok(());
    }
    let reader_ctx = ctx.clone();
    let reader_executor_tx = executor_tx.clone();
    let reader_writer_tx = writer_tx.clone();
    let reader_task = tokio::spawn(run_client_reader(
        reader,
        reader_executor_tx,
        reader_writer_tx,
        Some(reader_ctx.caffeinate_state_event()),
    ));
    let writer_task = tokio::spawn(async move {
        run_client_writer(writer, writer_rx).await;
        Ok::<(), anyhow::Error>(())
    });
    let event_ctx = ctx.clone();
    let event_principal = principal.clone();
    let event_executor_tx = executor_tx.clone();
    let event_writer_tx = writer_tx.clone();
    let event_task = tokio::spawn(async move {
        run_client_event_forwarder(
            event_ctx.clone(),
            event_principal,
            event_ctx.subscribe_global(),
            event_cmd_rx,
            event_executor_tx,
            event_writer_tx,
        )
        .await;
        Ok::<(), anyhow::Error>(())
    });
    let executor_task = tokio::spawn(run_client_executor(
        ctx.clone(),
        principal,
        client_instance_id,
        next_terminal_connection_epoch(),
        executor_rx,
        event_cmd_tx,
        writer_tx,
    ));

    let mut reader_task = reader_task;
    let mut writer_task = writer_task;
    let mut event_task = event_task;
    let mut executor_task = executor_task;

    let completed = select_client_task(
        &mut reader_task,
        &mut writer_task,
        &mut event_task,
        &mut executor_task,
    )
    .await;

    // The executor is the only transport task able to mint a sealed
    // capability. Terminate and join it before settling the connection's
    // capability set so no dispatch child can insert after cancellation.
    if completed.kind != ClientTaskKind::Executor {
        executor_task.abort();
        let _ = (&mut executor_task).await;
    }
    reader_task.abort();
    writer_task.abort();
    event_task.abort();
    if completed.kind != ClientTaskKind::Reader {
        let _ = (&mut reader_task).await;
    }
    if completed.kind != ClientTaskKind::Writer {
        let _ = (&mut writer_task).await;
    }
    if completed.kind != ClientTaskKind::Event {
        let _ = (&mut event_task).await;
    }
    let cancelled_capabilities = ctx
        .sealed_owner_capabilities
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .cancel_for_session(client_instance_id);
    if cancelled_capabilities > 0 {
        tracing::debug!(
            client_instance_id = %client_instance_id,
            cancelled_capabilities,
            "cancelled sealed capabilities at client transport teardown"
        );
    }
    completed.result?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientTaskKind {
    Reader,
    Writer,
    Event,
    Executor,
}

struct CompletedClientTask {
    kind: ClientTaskKind,
    result: Result<()>,
}

async fn select_client_task(
    reader: &mut tokio::task::JoinHandle<Result<()>>,
    writer: &mut tokio::task::JoinHandle<Result<()>>,
    event: &mut tokio::task::JoinHandle<Result<()>>,
    executor: &mut tokio::task::JoinHandle<Result<()>>,
) -> CompletedClientTask {
    tokio::select! {
        biased;
        result = executor => CompletedClientTask { kind: ClientTaskKind::Executor, result: flatten_client_task(result, "client executor task", false) },
        result = reader => CompletedClientTask { kind: ClientTaskKind::Reader, result: flatten_client_task(result, "client reader task", true) },
        result = writer => CompletedClientTask { kind: ClientTaskKind::Writer, result: flatten_client_task(result, "client writer task", false) },
        result = event => CompletedClientTask { kind: ClientTaskKind::Event, result: flatten_client_task(result, "client event task", false) },
    }
}

fn flatten_client_task(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    label: &str,
    clean_exit_is_normal: bool,
) -> Result<()> {
    let result = result
        .with_context(|| format!("{label} join failed"))?
        .with_context(|| format!("{label} failed"));
    match result {
        Ok(()) if clean_exit_is_normal => Ok(()),
        Ok(()) => anyhow::bail!("{label} ended unexpectedly"),
        Err(error) => Err(error),
    }
}

enum ClientExecutorInput {
    Frame(RecvFrame),
    SessionEventsClosed,
}

enum ClientWriterMessage {
    SetVersion(u32),
    Envelope(Envelope),
    EnvelopeWithAck {
        envelope: Envelope,
        ack: oneshot::Sender<std::result::Result<(), String>>,
    },
}

enum ClientEventCommand {
    Attach { session_id: Uuid, rx: EventReceiver },
    Detach,
}

async fn send_writer_envelope(
    writer_tx: &mpsc::Sender<ClientWriterMessage>,
    envelope: Envelope,
) -> bool {
    writer_tx
        .send(ClientWriterMessage::Envelope(envelope))
        .await
        .is_ok()
}

async fn send_writer_envelope_with_ack(
    writer_tx: &mpsc::Sender<ClientWriterMessage>,
    envelope: Envelope,
) -> bool {
    let (ack_tx, ack_rx) = oneshot::channel();
    if writer_tx
        .send(ClientWriterMessage::EnvelopeWithAck {
            envelope,
            ack: ack_tx,
        })
        .await
        .is_err()
    {
        return false;
    }
    matches!(ack_rx.await, Ok(Ok(())))
}

async fn run_client_reader<R>(
    mut reader: ProtoReadHalf<R>,
    executor_tx: mpsc::Sender<ClientExecutorInput>,
    writer_tx: mpsc::Sender<ClientWriterMessage>,
    initial_event_after_negotiation: Option<proto::Event>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let mut initial_event_after_negotiation = initial_event_after_negotiation;
    loop {
        match reader.recv().await {
            Ok(Some(frame)) => {
                // A protocol-version mismatch terminates the connection. The
                // executor is never allowed to exit cleanly (see
                // `select_client_task`), so the close must run here in the
                // reader — the one task whose clean exit is normal. Answer a
                // versioned request with a `ProtocolVersion` error (flushed via
                // ack) before closing, then exit cleanly.
                if let RecvFrame::VersionMismatch { v, kind, id } = &frame {
                    if kind == "req"
                        && let Some(id) = id
                    {
                        let envelope = Envelope::error(
                            Some(*id),
                            ErrorPayload {
                                code: ErrorCode::ProtocolVersion,
                                message: proto::version_mismatch_message(*v),
                            },
                        );
                        let _ = send_writer_envelope_with_ack(&writer_tx, envelope).await;
                    } else {
                        tracing::debug!(
                            version = *v,
                            kind = kind.as_str(),
                            ?id,
                            "closing client after protocol version mismatch"
                        );
                    }
                    return Ok(());
                }
                if let Some(version) = negotiated_writer_version_for_frame(&frame) {
                    if writer_tx
                        .send(ClientWriterMessage::SetVersion(version))
                        .await
                        .is_err()
                    {
                        anyhow::bail!("client reader lost writer control channel");
                    }
                    if let Some(event) = initial_event_after_negotiation.take()
                        && writer_tx
                            .send(ClientWriterMessage::Envelope(Envelope::event(event)))
                            .await
                            .is_err()
                    {
                        anyhow::bail!("client reader lost writer event channel");
                    }
                }
                if executor_tx
                    .send(ClientExecutorInput::Frame(frame))
                    .await
                    .is_err()
                {
                    anyhow::bail!("client reader lost executor channel");
                }
            }
            Ok(None) => return Ok(()),
            Err(error) => return Err(error.context("decoding client envelope")),
        }
    }
}

fn negotiated_writer_version_for_frame(frame: &RecvFrame) -> Option<u32> {
    match frame {
        RecvFrame::Envelope(env) => Some(env.v.min(proto::PROTOCOL_VERSION)),
        RecvFrame::Unknown { v, .. } => Some((*v).min(proto::PROTOCOL_VERSION)),
        RecvFrame::VersionMismatch { .. } => None,
    }
}

async fn run_client_writer<W>(
    mut writer: ProtoWriteHalf<W>,
    mut writer_rx: mpsc::Receiver<ClientWriterMessage>,
) where
    W: AsyncWrite + Unpin + Send + 'static,
{
    while let Some(message) = writer_rx.recv().await {
        let (envelope, ack) = match message {
            ClientWriterMessage::SetVersion(version) => {
                writer.set_negotiated_version(version);
                continue;
            }
            ClientWriterMessage::Envelope(envelope) => (envelope, None),
            ClientWriterMessage::EnvelopeWithAck { envelope, ack } => (envelope, Some(ack)),
        };
        let result = writer.send(&envelope).await;
        if let Some(ack) = ack {
            let _ = ack.send(result.as_ref().map(|_| ()).map_err(ToString::to_string));
        }
        if let Err(e) = result {
            tracing::debug!(error = ?e, "client disconnected during envelope send");
            return;
        }
    }
}

async fn run_client_event_forwarder(
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
    mut global_rx: EventReceiver,
    mut event_cmd_rx: mpsc::Receiver<ClientEventCommand>,
    executor_tx: mpsc::Sender<ClientExecutorInput>,
    writer_tx: mpsc::Sender<ClientWriterMessage>,
) {
    let mut session_event_rx: Option<EventReceiver> = None;
    let mut session_id: Option<Uuid> = None;
    loop {
        let session_branch = async {
            match session_event_rx.as_mut() {
                Some(rx) => Some(rx.recv().await),
                None => std::future::pending().await,
            }
        };

        tokio::select! {
            biased;
            cmd = event_cmd_rx.recv() => {
                match cmd {
                    Some(ClientEventCommand::Attach { session_id: id, rx }) => {
                        session_id = Some(id);
                        session_event_rx = Some(rx);
                    }
                    Some(ClientEventCommand::Detach) => {
                        session_id = None;
                        session_event_rx = None;
                    }
                    None => return,
                }
            }
            global = global_rx.recv() => {
                match global {
                    Ok(envelope) => {
                        let Some(event) = scrub_event_for_principal(&principal, envelope) else {
                            continue;
                        };
                        if !send_writer_envelope(&writer_tx, Envelope::event(event)).await {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(missed = n, "client global event stream lagged");
                        if !send_writer_envelope(
                            &writer_tx,
                            Envelope::event(ctx.caffeinate_state_event()),
                        )
                        .await
                        {
                            return;
                        }
                        if let Some(event) = ctx.drain_state_event()
                            && !send_writer_envelope(&writer_tx, Envelope::event(event)).await
                        {
                            return;
                        }
                        if !send_writer_envelope(
                            &writer_tx,
                            Envelope::event(proto::Event::EventStreamLagged {
                                session_id: None,
                                dropped: n,
                            }),
                        )
                        .await
                        {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {}
                }
            }
            event = session_branch => {
                match event {
                    Some(Ok(envelope)) => {
                        let Some(event) = scrub_event_for_principal(&principal, envelope) else {
                            continue;
                        };
                        // A raised/resolved interrupt moves the project's
                        // interruptions count. The worker's single forwarder
                        // recomputes and broadcasts the global plan-status
                        // state once per interrupt event; this per-client fan-
                        // out path only forwards the interrupt itself.
                        if !send_writer_envelope(&writer_tx, Envelope::event(event)).await {
                            return;
                        }
                    }
                    Some(Err(broadcast::error::RecvError::Lagged(n))) => {
                        tracing::warn!(missed = n, "client event stream lagged; reattach to resync");
                        let _ = send_writer_envelope(
                            &writer_tx,
                            Envelope::event(proto::Event::EventStreamLagged {
                                session_id,
                                dropped: n,
                            }),
                        )
                        .await;
                    }
                    Some(Err(broadcast::error::RecvError::Closed)) => {
                        session_id = None;
                        session_event_rx = None;
                        let _ = executor_tx.send(ClientExecutorInput::SessionEventsClosed).await;
                    }
                    None => unreachable!("session_branch is pending when not attached"),
                }
            }
        }
    }
}

async fn run_client_executor(
    ctx: Arc<DaemonContext>,
    principal: ClientPrincipal,
    client_instance_id: Uuid,
    connection_epoch: u64,
    mut executor_rx: mpsc::Receiver<ClientExecutorInput>,
    event_cmd_tx: mpsc::Sender<ClientEventCommand>,
    writer_tx: mpsc::Sender<ClientWriterMessage>,
) -> Result<()> {
    let mut state = MutableClientState::detached_with_principal(
        ctx.upload_accounting.clone(),
        principal,
        ctx.terminal_host.clone(),
        client_instance_id,
        connection_epoch,
    );
    let mut shared = state.shared_snapshot();
    let mut concurrent = ConcurrentRequestRuntime::new();
    loop {
        tokio::select! {
            biased;
            Some(joined) = concurrent.join_next(), if !concurrent.is_empty() => {
                if let Err(error) = joined {
                    tracing::warn!(%error, "concurrent request task failed");
                }
            }
            input = executor_rx.recv() => {
                let Some(input) = input else {
                    if let Err(error) = attachments::drain_client_attachment_ownership(&mut state, &ctx, "disconnect").await {
                        tracing::warn!(message=%error.message,"attachment ownership drain failed during disconnect; durable charges remain for retry recovery");
                    }
                    return Ok(());
                };
                match input {
                    ClientExecutorInput::Frame(frame) => {
                        if !handle_client_frame(
                            frame,
                            &mut state,
                            &mut shared,
                            &ctx,
                            &event_cmd_tx,
                            &writer_tx,
                            &mut concurrent,
                        )
                        .await?
                        {
                            return Ok(());
                        }
                    }
                    ClientExecutorInput::SessionEventsClosed => {
                        state.attached = None;
                        shared = state.shared_snapshot();
                    }
                }
            }
        }
    }
}

async fn handle_client_frame(
    frame: RecvFrame,
    state: &mut MutableClientState,
    shared: &mut Arc<SharedClientState>,
    ctx: &Arc<DaemonContext>,
    event_cmd_tx: &mpsc::Sender<ClientEventCommand>,
    writer_tx: &mpsc::Sender<ClientWriterMessage>,
    concurrent: &mut ConcurrentRequestRuntime,
) -> Result<bool> {
    match frame {
        RecvFrame::Envelope(env) => handle_envelope(
            *env,
            state,
            shared,
            ctx,
            event_cmd_tx,
            writer_tx,
            concurrent,
        )
        .await
        .map(|()| true),
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
                let _ = send_writer_envelope_with_ack(writer_tx, envelope).await;
            } else {
                tracing::debug!(
                    version = v,
                    kind,
                    ?id,
                    "closing client after protocol version mismatch"
                );
            }
            Ok(false)
        }
        RecvFrame::Unknown { v, kind, tag, id } => {
            if kind == "req"
                && let Some(id) = id
            {
                let envelope = Envelope::error(
                    Some(id),
                    proto::unsupported_request_error(v, tag.as_deref()),
                );
                let _ = send_writer_envelope_with_ack(writer_tx, envelope).await;
            } else {
                tracing::debug!(
                    version = v,
                    kind,
                    ?tag,
                    ?id,
                    "dropping unknown protocol frame"
                );
            }
            Ok(true)
        }
    }
}

async fn handle_envelope(
    env: Envelope,
    state: &mut MutableClientState,
    shared: &mut Arc<SharedClientState>,
    ctx: &Arc<DaemonContext>,
    event_cmd_tx: &mpsc::Sender<ClientEventCommand>,
    writer_tx: &mpsc::Sender<ClientWriterMessage>,
    concurrent: &mut ConcurrentRequestRuntime,
) -> Result<()> {
    // Track the negotiated protocol version for this connection so v10-only
    // semantic changes can gate on it. The envelope version is the
    // min(client, daemon) negotiated value.
    state.update_negotiated_protocol_version(env.v);
    match env.body {
        Body::Request {
            id,
            #[cfg(feature = "remote")]
            operation,
            request,
        } => {
            #[cfg(feature = "remote")]
            let remote_operation = match remote_dispatch::admit(
                ctx,
                &state.principal,
                id,
                operation,
                &request,
            )
            .await
            {
                Ok(context) => context,
                Err(error) => {
                    let envelope = Envelope::error(Some(id), error);
                    let _ = send_writer_envelope(writer_tx, envelope).await;
                    return Ok(());
                }
            };
            if principal::request_ordering(&request) == principal::RequestOrdering::Concurrent {
                let Ok(permit) = concurrent.permits.clone().acquire_owned().await else {
                    return Ok(());
                };
                let request_shared = shared.clone();
                let ctx = ctx.clone();
                let writer_tx = writer_tx.clone();
                concurrent.tasks.spawn(async move {
                    let _permit = permit;
                    let response_shared = request_shared.clone();
                    let response_ctx = ctx.clone();
                    #[cfg(feature = "remote")]
                    let result = run_concurrent_request_catching_panic_with_remote_operation(
                        request,
                        request_shared,
                        ctx,
                        remote_operation,
                    )
                    .await;
                    #[cfg(not(feature = "remote"))]
                    let result =
                        run_concurrent_request_catching_panic(request, request_shared, ctx).await;
                    let envelope =
                        response_envelope_for_shared(id, result, &response_shared, &response_ctx);
                    let _ = send_writer_envelope(&writer_tx, envelope).await;
                });
                return Ok(());
            }
            let is_attach = matches!(&request, Request::Attach { .. });
            let mut effects = ClientRequestEffects::default();
            #[cfg(feature = "remote")]
            let result = Box::pin(
                dispatch::handle_serialized_request_with_remote_operation_id(
                    id,
                    request,
                    state,
                    shared,
                    ctx,
                    &mut effects,
                    remote_operation.as_ref(),
                ),
            )
            .await;
            #[cfg(not(feature = "remote"))]
            let result = Box::pin(dispatch::handle_serialized_request_with_id(
                id,
                request,
                state,
                shared,
                ctx,
                &mut effects,
            ))
            .await;
            let attached = matches!(&result, Ok(Response::Attached { .. }));
            if (is_attach && attached) || state.attached.is_none() {
                *shared = state.shared_snapshot();
            }
            let envelope = response_envelope_for_shared(id, result, shared, ctx);
            let envelope_kind = envelope_kind(&envelope);
            let sent = if effects.shutdown_after_response {
                send_writer_envelope_with_ack(writer_tx, envelope).await
            } else {
                send_writer_envelope(writer_tx, envelope).await
            };
            if !sent {
                log_response_send_failed(
                    id,
                    envelope_kind,
                    &anyhow::anyhow!("client writer task ended"),
                );
                if effects.shutdown_after_response {
                    request_shutdown(ctx);
                }
                return Ok(());
            }
            if effects.shutdown_after_response {
                request_shutdown(ctx);
            }
            if is_attach && attached {
                for event in std::mem::take(&mut state.pending_replay) {
                    let Some(event) = scrub_replay_event_for_principal(shared, event) else {
                        continue;
                    };
                    if !send_writer_envelope(writer_tx, Envelope::event(event)).await {
                        tracing::debug!("client disconnected during attach replay");
                        return Ok(());
                    }
                }
                if let Some(event) = ctx.drain_state_event() {
                    let _ = send_writer_envelope(writer_tx, Envelope::event(event)).await;
                }
                if let Some(rx) = effects.session_event_rx.take() {
                    let session_id = state
                        .attached
                        .as_ref()
                        .map(|attached| attached.handle.session_id);
                    if let Some(session_id) = session_id {
                        let _ = event_cmd_tx
                            .send(ClientEventCommand::Attach { session_id, rx })
                            .await;
                    }
                }
            } else if state.attached.is_none() {
                let _ = event_cmd_tx.send(ClientEventCommand::Detach).await;
            }
        }
        #[cfg(feature = "remote")]
        Body::RemoteReplayRequest(proto::RemoteReplayRequestV2 {
            id,
            after_event_seq,
            limit,
        }) => {
            let ClientPrincipal::Remote(remote) = &state.principal else {
                let _ = send_writer_envelope(
                    writer_tx,
                    Envelope::error(
                        Some(id),
                        ErrorPayload {
                            code: ErrorCode::Authorization,
                            message: "remote replay requires an authenticated actor".into(),
                        },
                    ),
                )
                .await;
                return Ok(());
            };
            let Some(actor) = remote.actor_binding.as_ref() else {
                let _ = send_writer_envelope(
                    writer_tx,
                    Envelope::error(
                        Some(id),
                        ErrorPayload {
                            code: ErrorCode::Authorization,
                            message: "legacy actorless transport cannot replay mutations".into(),
                        },
                    ),
                )
                .await;
                return Ok(());
            };
            let attachment = actor.logical_attachment_id.to_string();
            let consumer = format!("t:{}:{}", actor.device_id.simple(), actor.device_generation);
            let mut cursor = after_event_seq
                .as_ref()
                .map(|value| value.value())
                .unwrap_or(0);
            let mut events = Vec::with_capacity(limit.get() as usize);
            for _ in 0..limit.get() {
                let Some(lease) = ctx
                    .db
                    .claim_remote_outbox_delivery(
                        &consumer,
                        "*",
                        Some(&attachment),
                        Some(cursor),
                        chrono::Utc::now().timestamp_millis(),
                        30_000,
                    )
                    .await?
                else {
                    break;
                };
                cursor = lease.event_seq;
                events.push(proto::RemoteOutboxDeliveryV1 {
                    event_seq: proto::remote_protocol_id::CanonicalU64DecimalStringV1::from_u64(
                        lease.event_seq,
                    ),
                    delivery_id: proto::CanonicalRfcUuidV1::new(Uuid::parse_str(
                        &lease.delivery_id,
                    )?)?,
                    kind: lease.kind,
                    canonical_payload: lease.canonical_payload,
                    lease_token: proto::CanonicalRfcUuidV1::new(Uuid::parse_str(&lease.lease_id)?)?,
                    lease_expires_at_ms: lease.lease_expires_at_ms,
                });
            }
            let high_water = ctx.db.remote_outbox_high_water(&attachment).await?;
            let envelope = Envelope {
                v: proto::PROTOCOL_VERSION,
                body: Body::RemoteReplayResponse(proto::RemoteReplayResponseV2 {
                    id,
                    events,
                    high_water_mark:
                        proto::remote_protocol_id::CanonicalU64DecimalStringV1::from_u64(high_water),
                }),
            };
            let _ = send_writer_envelope(writer_tx, envelope).await;
        }
        #[cfg(feature = "remote")]
        Body::RemoteReplayAck(proto::RemoteReplayAckV2 {
            id,
            delivery_id,
            lease_token,
        }) => {
            let ClientPrincipal::Remote(remote) = &state.principal else {
                let _ = send_writer_envelope(
                    writer_tx,
                    Envelope::error(
                        Some(id),
                        ErrorPayload {
                            code: ErrorCode::Authorization,
                            message:
                                "remote replay acknowledgement requires an authenticated actor"
                                    .into(),
                        },
                    ),
                )
                .await;
                return Ok(());
            };
            let Some(actor) = remote.actor_binding.as_ref() else {
                let _ = send_writer_envelope(
                    writer_tx,
                    Envelope::error(
                        Some(id),
                        ErrorPayload {
                            code: ErrorCode::Authorization,
                            message: "legacy actorless transport cannot acknowledge replay".into(),
                        },
                    ),
                )
                .await;
                return Ok(());
            };
            let attachment = actor.logical_attachment_id.to_string();
            let consumer = format!("t:{}:{}", actor.device_id.simple(), actor.device_generation);
            let acked = ctx
                .db
                .ack_remote_outbox_delivery(
                    &attachment,
                    &delivery_id.get().to_string(),
                    &consumer,
                    &lease_token.get().to_string(),
                    chrono::Utc::now().timestamp_millis(),
                )
                .await?;
            let _ = send_writer_envelope(
                writer_tx,
                Envelope {
                    v: proto::PROTOCOL_VERSION,
                    body: Body::RemoteReplayAckResponse(proto::RemoteReplayAckResponseV2 {
                        id,
                        acked,
                    }),
                },
            )
            .await;
        }
        #[cfg(feature = "remote")]
        Body::RemoteReplayResponse(proto::RemoteReplayResponseV2 { id, .. })
        | Body::RemoteReplayAckResponse(proto::RemoteReplayAckResponseV2 { id, .. }) => {
            tracing::warn!(%id, "client sent a replay response; ignoring");
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
        Body::Unknown => {
            tracing::debug!("dropping unknown client protocol body");
        }
    }
    Ok(())
}

async fn run_concurrent_request_catching_panic(
    request: Request,
    shared: Arc<SharedClientState>,
    ctx: Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    match AssertUnwindSafe(dispatch::handle_concurrent_request(request, shared, ctx))
        .catch_unwind()
        .await
    {
        Ok(result) => result,
        Err(_) => Err(ErrorPayload {
            code: ErrorCode::Internal,
            message: "concurrent request handler panicked".to_string(),
        }),
    }
}

#[cfg(feature = "remote")]
async fn run_concurrent_request_catching_panic_with_remote_operation(
    request: Request,
    shared: Arc<SharedClientState>,
    ctx: Arc<DaemonContext>,
    remote_operation: Option<remote_dispatch::RemoteOperationContext>,
) -> std::result::Result<Response, ErrorPayload> {
    match AssertUnwindSafe(dispatch::handle_concurrent_request_with_remote_operation(
        request,
        shared,
        ctx,
        remote_operation,
    ))
    .catch_unwind()
    .await
    {
        Ok(result) => result,
        Err(_) => Err(ErrorPayload {
            code: ErrorCode::Internal,
            message: "concurrent request handler panicked".to_string(),
        }),
    }
}

#[cfg(test)]
#[derive(Default)]
struct ConcurrentRequestTestHooks {
    waits: StdMutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    entered: StdMutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    panics: StdMutex<HashSet<String>>,
}

#[cfg(test)]
fn concurrent_request_test_hooks() -> &'static ConcurrentRequestTestHooks {
    static HOOKS: OnceLock<ConcurrentRequestTestHooks> = OnceLock::new();
    HOOKS.get_or_init(ConcurrentRequestTestHooks::default)
}

#[cfg(test)]
fn concurrent_request_test_key(request: &Request) -> Option<String> {
    match request {
        Request::FsRead {
            project_root, path, ..
        } => Some(format!("fs_read:{project_root}:{path}")),
        _ => None,
    }
}

#[cfg(test)]
fn set_concurrent_request_wait_for_test(
    key: String,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
) {
    let hooks = concurrent_request_test_hooks();
    hooks.entered.lock().unwrap().insert(key.clone(), entered);
    hooks.waits.lock().unwrap().insert(key, release);
}

#[cfg(test)]
fn set_concurrent_request_panic_for_test(key: String) {
    concurrent_request_test_hooks()
        .panics
        .lock()
        .unwrap()
        .insert(key);
}

#[cfg(test)]
async fn apply_concurrent_request_test_hook(request: &Request) {
    let Some(key) = concurrent_request_test_key(request) else {
        return;
    };
    let hooks = concurrent_request_test_hooks();
    if let Some(entered) = hooks.entered.lock().unwrap().remove(&key) {
        entered.notify_waiters();
    }
    if hooks.panics.lock().unwrap().remove(&key) {
        panic!("concurrent request test hook panic");
    }
    let wait = hooks.waits.lock().unwrap().remove(&key);
    if let Some(wait) = wait {
        wait.notified().await;
    }
}

fn response_envelope_for_shared(
    id: Uuid,
    result: std::result::Result<Response, ErrorPayload>,
    shared: &SharedClientState,
    ctx: &DaemonContext,
) -> Envelope {
    match result {
        Ok(response) => {
            let response = if shared.principal.is_owner() {
                // Owner responses are trusted, but still pass through the
                // daemon-global redaction table as defense in depth: any known
                // vault/env secret value that leaked into a response (for
                // example an inline credential a serializer failed to strip)
                // is neutralized before it crosses the socket. This is a
                // backstop; secret-bearing payloads must be sanitized
                // structurally at their source (see `policy::export`).
                let mut response = response;
                scrub_response_free_text(&mut response, &current_redaction(&ctx.global_redaction));
                Some(response)
            } else if let Some(attached) = shared.attached.as_ref() {
                scrub_proto_response(response, &attached.redaction_table())
            } else {
                // Session-bearing responses without an attachment must scrub
                // inside their request arm using the target session's
                // persisted table (for example `SubagentTranscript`). Other
                // unattached responses do not carry session user content.
                Some(response)
            };
            match response {
                Some(mut response) => {
                    finalize_response_projections(&mut response, &ctx.secret_vault);
                    bounded_response_envelope(id, response)
                }
                None => bounded_error_envelope(
                    Some(id),
                    ErrorPayload {
                        code: ErrorCode::Internal,
                        message: "response redaction failed".to_string(),
                    },
                ),
            }
        }
        Err(err) => bounded_error_envelope(Some(id), normalize_database_storage_error(err)),
    }
}

fn bounded_response_envelope(id: Uuid, response: proto::Response) -> Envelope {
    if !local_authority_response_within_bounds(&response) {
        return bounded_error_envelope(
            Some(id),
            ErrorPayload {
                code: ErrorCode::Internal,
                message: "daemon authority projection exceeds its safe local response bounds; reduce the local inventory or authored file size".into(),
            },
        );
    }
    let envelope = Envelope::response(id, response);
    if serde_json::to_vec(&envelope)
        .is_ok_and(|bytes| bytes.len().saturating_add(1) <= proto::MAX_SERIALIZED_RESPONSE_BYTES)
    {
        envelope
    } else {
        bounded_error_envelope(
            Some(id),
            ErrorPayload {
                code: ErrorCode::Internal,
                message: "response exceeds the safe local protocol budget; narrow the request or reduce the local inventory".into(),
            },
        )
    }
}

fn local_authority_response_within_bounds(response: &proto::Response) -> bool {
    let assistant =
        |summary: &proto::AssistantSummary| proto::validate_assistant_summary(summary).is_ok();
    let agent_snapshot =
        |snapshot: &proto::AgentEditSnapshot| proto::validate_agent_edit_snapshot(snapshot).is_ok();
    let inventory_entry = |entry: &proto::AgentInventoryEntry| {
        entry.name.len() <= proto::MAX_AGENT_NAME_BYTES
            && [
                entry.description.as_deref(),
                entry.model.as_deref(),
                entry.diagnostic.as_deref(),
            ]
            .into_iter()
            .flatten()
            .all(|value| value.len() <= proto::MAX_AGENT_METADATA_BYTES)
            && proto::is_opaque_authority_token(&entry.source_identity)
            && proto::is_opaque_authority_token(&entry.revision)
            && proto::is_opaque_authority_token(&entry.projection_digest)
    };
    let assistant_receipt = |operation: &str,
                             intent: &str,
                             root: &str,
                             requested_root: &str,
                             name: &str,
                             consumed: &str,
                             result: &str,
                             consumed_generation: u64,
                             result_generation: u64,
                             outcome: &proto::AgentMutationOutcome| {
        !operation.is_empty()
            && operation.len() <= 128
            && proto::is_opaque_authority_token(intent)
            && !root.is_empty()
            && root.len() <= proto::MAX_OWNER_PROJECT_ROOT_BYTES
            && !requested_root.is_empty()
            && requested_root.len() <= proto::MAX_OWNER_PROJECT_ROOT_BYTES
            && !name.is_empty()
            && name.len() <= proto::MAX_AGENT_NAME_BYTES
            && !consumed.is_empty()
            && consumed.len() <= 128
            && proto::is_opaque_authority_token(result)
            && (matches!(outcome, proto::AgentMutationOutcome::Reconciled)
                || result_generation > consumed_generation)
    };
    match response {
        proto::Response::Assistant { assistant: value } => value.as_ref().is_none_or(assistant),
        proto::Response::Assistants { assistants, .. } => {
            assistants.len() <= proto::MAX_ASSISTANT_SUMMARIES && assistants.iter().all(assistant)
        }
        proto::Response::AssistantUpserted { assistant: value } => assistant(value),
        proto::Response::AssistantDefinitionSaved {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            requested_project_root,
            name,
            assistant: value,
            consumed_revision,
            result_revision,
            consumed_config_generation,
            result_config_generation,
            outcome,
        } => {
            value.as_ref().is_none_or(assistant)
                && assistant_receipt(
                    client_operation_id,
                    mutation_intent_hash,
                    project_root,
                    requested_project_root,
                    name,
                    consumed_revision,
                    result_revision,
                    *consumed_config_generation,
                    *result_config_generation,
                    outcome,
                )
        }
        proto::Response::AssistantDeleted {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            requested_project_root,
            name,
            consumed_revision,
            result_revision,
            consumed_config_generation,
            result_config_generation,
            outcome,
        } => assistant_receipt(
            client_operation_id,
            mutation_intent_hash,
            project_root,
            requested_project_root,
            name,
            consumed_revision,
            result_revision,
            *consumed_config_generation,
            *result_config_generation,
            outcome,
        ),
        proto::Response::ExtendedConfigSnapshot { layers, .. } => {
            layers.len() <= proto::MAX_EXTENDED_CONFIG_LAYERS
                && layers.iter().all(|layer| {
                    layer.display_path.len() <= proto::MAX_AGENT_METADATA_BYTES
                        && layer.denylist.len() <= proto::MAX_AGENT_INVENTORY_ENTRIES
                        && serde_json::to_vec(layer).is_ok_and(|bytes| {
                            bytes.len() <= proto::MAX_EXTENDED_CONFIG_SOURCE_BYTES
                        })
                })
        }
        proto::Response::ExtendedConfigSaved { denylist, .. } => {
            let mut result_ids = std::collections::HashSet::new();
            let mut consumed_ids = std::collections::HashSet::new();
            let mut nonces = std::collections::HashSet::new();
            denylist.len() <= proto::MAX_AGENT_INVENTORY_ENTRIES
                && denylist.iter().all(|entry| {
                    proto::is_opaque_authority_token(&entry.entry_id)
                        && result_ids.insert(entry.entry_id.as_str())
                        && entry.display_mask == proto::REDACTED_DENYLIST_MASK
                        && match (&entry.consumed_entry_id, &entry.client_nonce) {
                            (Some(consumed), None) => {
                                proto::is_opaque_authority_token(consumed)
                                    && consumed_ids.insert(consumed.as_str())
                            }
                            (None, Some(nonce)) => {
                                uuid::Uuid::parse_str(nonce)
                                    .is_ok_and(|parsed| parsed.to_string() == *nonce)
                                    && nonces.insert(nonce.as_str())
                            }
                            _ => false,
                        }
                })
        }
        proto::Response::AgentInventory { entries, .. } => {
            entries.len() <= proto::MAX_AGENT_INVENTORY_ENTRIES
                && entries.iter().all(inventory_entry)
        }
        proto::Response::AgentEditSnapshot(value) => agent_snapshot(value),
        proto::Response::AgentMutated(result) => {
            result.snapshot.as_ref().is_none_or(agent_snapshot)
        }
        proto::Response::AgentEditorLeaseCompleted(result) => {
            proto::is_opaque_authority_token(&result.consumed_revision)
                && result.client_operation_id.len() <= 128
                && result.lease_id.len() <= 128
                && result.agent_name.len() <= proto::MAX_AGENT_NAME_BYTES
                && result.project_root.len() <= proto::MAX_OWNER_PROJECT_ROOT_BYTES
                && match &result.status {
                    proto::AgentEditorSettlementStatus::Saved {
                        result_revision, ..
                    } => proto::is_opaque_authority_token(result_revision),
                    proto::AgentEditorSettlementStatus::Rejected { error } => {
                        error.message.len() <= proto::MAX_AGENT_METADATA_BYTES
                    }
                    proto::AgentEditorSettlementStatus::NotStarted
                    | proto::AgentEditorSettlementStatus::Pending
                    | proto::AgentEditorSettlementStatus::Cancelled => true,
                }
        }
        proto::Response::AgentEditorLeaseBegun(lease) => {
            !lease.client_operation_id.is_empty()
                && lease.client_operation_id.len() <= 128
                && !lease.lease_id.is_empty()
                && lease.lease_id.len() <= 128
                && agent_snapshot(&lease.snapshot)
        }
        _ => true,
    }
}

fn bounded_error_envelope(id: Option<Uuid>, error: ErrorPayload) -> Envelope {
    let envelope = Envelope::error(id, error);
    if serde_json::to_vec(&envelope)
        .is_ok_and(|bytes| bytes.len().saturating_add(1) <= proto::MAX_SERIALIZED_RESPONSE_BYTES)
    {
        envelope
    } else {
        Envelope::error(
            id,
            ErrorPayload {
                code: ErrorCode::Internal,
                message:
                    "daemon response could not be represented within the local protocol budget"
                        .into(),
            },
        )
    }
}

fn scrub_replay_event_for_principal(
    shared: &SharedClientState,
    event: proto::Event,
) -> Option<proto::Event> {
    if shared.principal.is_owner() {
        return Some(event);
    }
    let Some(attached) = shared.attached.as_ref() else {
        return Some(event);
    };
    scrub_proto_event(event, &attached.redaction_table())
}

fn envelope_kind(envelope: &Envelope) -> &'static str {
    match envelope.body {
        Body::Response { .. } => "response",
        Body::Error { .. } => "error",
        Body::Request { .. } => "request",
        Body::Event { .. } => "event",
        #[cfg(feature = "remote")]
        Body::RemoteReplayRequest(_) => "replay_request",
        #[cfg(feature = "remote")]
        Body::RemoteReplayResponse(_) => "replay_response",
        #[cfg(feature = "remote")]
        Body::RemoteReplayAck(_) => "replay_ack",
        #[cfg(feature = "remote")]
        Body::RemoteReplayAckResponse(_) => "replay_ack_response",
        Body::Unknown => "unknown",
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

fn normalize_database_storage_error(mut error: ErrorPayload) -> ErrorPayload {
    if error.code != ErrorCode::Internal {
        return error;
    }
    error.code = if error.message.contains("FCDB_STORAGE_FULL") {
        ErrorCode::StorageFull
    } else if error.message.contains("FCDB_STORAGE_MEMORY") {
        ErrorCode::StorageMemory
    } else if error.message.contains("FCDB_STORAGE_READ_ONLY") {
        ErrorCode::StorageReadOnly
    } else if error.message.contains("FCDB_STORAGE_IO") {
        ErrorCode::StorageIo
    } else if error.message.contains("FCDB_STORAGE_CORRUPT") {
        ErrorCode::StorageCorrupt
    } else {
        return error;
    };
    error
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

mod attachments;
mod authz;
mod dispatch;
#[cfg(feature = "remote")]
mod remote_dispatch;
#[cfg(feature = "remote")]
pub(crate) use remote_dispatch::RemoteOperationContext;
mod image_control_mutations;
mod image_control_reads;
mod run_invocation;
mod sealed_capabilities;
pub use run_invocation::{
    RemainingRestart as RunInvocationRemaining,
    principal_digest as run_invocation_principal_digest,
    remaining_after_restart_for_row as run_invocation_remaining_after_restart,
    wall_ms_now as run_invocation_wall_ms_now,
};
#[cfg(test)]
mod host_capabilities_tests;
pub(crate) mod inventory;
#[cfg(test)]
mod leaks_tests;
#[cfg(all(test, feature = "remote"))]
mod secret_store_boot_tests;
#[cfg(test)]
mod secret_store_local_tests;
mod sessions;
#[cfg(feature = "remote")]
mod sessions_remote;
#[cfg(test)]
mod tests;

pub use attachments::validate_png_attachment_blocking;
pub(crate) use dispatch::CONFIG_PUBLICATION_RPC_LOCK;
pub use dispatch::request_shutdown;
pub(crate) fn spawn_lock_sweeper(ctx: Arc<DaemonContext>) -> tokio::task::JoinHandle<()> {
    dispatch::spawn_lock_sweeper(ctx)
}
