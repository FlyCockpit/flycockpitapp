use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::engine::driver) struct NoninteractiveDelegationKey {
    pub(in crate::engine::driver) task_call_id: String,
    pub(in crate::engine::driver) label: String,
}

/// Explicit identity of the child lifecycle controlled by this run. Event
/// forwarding/steering is transport metadata and must not decide whether a
/// `subagentStop` policy boundary exists.
#[derive(Debug, Clone)]
pub(in crate::engine::driver) struct ChildHookLifecycle {
    subagent_id: String,
    start_event_emitted: bool,
    lifecycle_event_emitted: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ChildHookLifecycle {
    fn new(subagent_id: impl Into<String>) -> Self {
        Self {
            subagent_id: subagent_id.into(),
            start_event_emitted: false,
            lifecycle_event_emitted: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn already_started(subagent_id: impl Into<String>) -> Self {
        Self {
            subagent_id: subagent_id.into(),
            start_event_emitted: true,
            lifecycle_event_emitted: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn publish(&self, emitted: bool) {
        if emitted {
            self.lifecycle_event_emitted
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }

    fn emitted(&self) -> bool {
        self.lifecycle_event_emitted
            .load(std::sync::atomic::Ordering::Acquire)
    }
}

impl NoninteractiveDelegationKey {
    pub(crate) fn new(task_call_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            task_call_id: task_call_id.into(),
            label: label.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(in crate::engine::driver) enum NoninteractiveDelegationStatus {
    Running,
    Backgrounded,
    Completed,
    Failed,
    Cancelled,
    Lost,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(in crate::engine::driver) struct NoninteractiveDelegationSnapshot {
    pub(in crate::engine::driver) history: Vec<Message>,
}

impl NoninteractiveDelegationSnapshot {
    pub(in crate::engine::driver) fn empty() -> Self {
        Self {
            history: Vec::new(),
        }
    }

    pub(in crate::engine::driver) fn from_history(history: Vec<Message>) -> Self {
        Self { history }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(in crate::engine::driver) struct NoninteractiveSteer {
    pub(in crate::engine::driver) body: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(in crate::engine::driver) struct NoninteractiveCompletionPayload {
    pub(in crate::engine::driver) report: String,
    pub(in crate::engine::driver) failed: bool,
    pub(in crate::engine::driver) result: Option<Message>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(in crate::engine::driver) struct PartialProgressFileEdit {
    pub(in crate::engine::driver) path: String,
    pub(in crate::engine::driver) hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(in crate::engine::driver) struct PartialProgressCommand {
    pub(in crate::engine::driver) command: String,
    pub(in crate::engine::driver) verification: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub(in crate::engine::driver) struct DelegationPartialProgress {
    pub(in crate::engine::driver) files_read: Vec<String>,
    pub(in crate::engine::driver) files_edited: Vec<PartialProgressFileEdit>,
    pub(in crate::engine::driver) commands: Vec<PartialProgressCommand>,
    pub(in crate::engine::driver) last_action: Option<String>,
    pub(in crate::engine::driver) verification_state: Option<String>,
    pub(in crate::engine::driver) review_state: Option<String>,
    pub(in crate::engine::driver) dirty_owned_changes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(in crate::engine::driver) struct SubagentFailureEnvelope {
    pub(in crate::engine::driver) provider: String,
    pub(in crate::engine::driver) model: String,
    pub(in crate::engine::driver) error_class: crate::engine::model::InferenceErrorClass,
    pub(in crate::engine::driver) elapsed_ms: u64,
    pub(in crate::engine::driver) fallback_tried: Vec<crate::engine::agent::FailoverAttempt>,
    pub(in crate::engine::driver) suggested_action: String,
    /// Content-safe stand-in for the provider failure body. Always the fixed
    /// `provider_detail_omitted` marker (via [`crate::engine::model::safe_provider_detail`]);
    /// the raw provider text never enters this envelope, so it cannot leak
    /// through the serialized `subagent_report` event or the rendered report.
    pub(in crate::engine::driver) detail: String,
    /// Observed HTTP status class retained for diagnostics (queryable metadata
    /// that survives the raw-detail omission). `None` for pure timeout /
    /// transport failures.
    pub(in crate::engine::driver) observed_status: Option<u16>,
    /// Typed provider-recovery signal (queryable metadata that survives the
    /// raw-detail omission).
    pub(in crate::engine::driver) recovery: crate::engine::model::ProviderRecoverySignal,
}

impl SubagentFailureEnvelope {
    pub(in crate::engine::driver) fn from_error(
        source: &anyhow::Error,
        fallback_tried: Vec<crate::engine::agent::FailoverAttempt>,
    ) -> Option<Self> {
        let failure = crate::engine::model::as_inference_failure(source)?;
        // Route the raw provider detail through the omission funnel: the
        // envelope carries the fixed marker plus the typed classification
        // metadata, never the provider body.
        let safe = crate::engine::model::safe_provider_detail(failure);
        Some(Self {
            provider: failure.provider.clone(),
            model: failure.model.clone(),
            error_class: failure.class.clone(),
            elapsed_ms: failure.elapsed_ms,
            fallback_tried,
            suggested_action: crate::engine::agent::suggested_action_for_failure_class(
                &failure.class,
            )
            .to_string(),
            detail: safe.marker_string(),
            observed_status: safe.observed_status,
            recovery: safe.recovery,
        })
    }
}

impl DelegationPartialProgress {
    pub(in crate::engine::driver) fn is_empty(&self) -> bool {
        self.files_read.is_empty()
            && self.files_edited.is_empty()
            && self.commands.is_empty()
            && self.last_action.is_none()
            && self.verification_state.is_none()
            && self.review_state.is_none()
            && self.dirty_owned_changes.is_empty()
    }
}

#[derive(Debug, Clone)]
pub(in crate::engine::driver) struct DelegationChildOutcome {
    pub(in crate::engine::driver) report: String,
    pub(in crate::engine::driver) failed: bool,
    pub(in crate::engine::driver) failure: Option<SubagentFailureEnvelope>,
    pub(in crate::engine::driver) partial_progress: DelegationPartialProgress,
    pub(in crate::engine::driver) child_routing: Option<ChildRoutingMetadata>,
}

impl DelegationChildOutcome {
    pub(in crate::engine::driver) fn ok(report: impl Into<String>) -> Self {
        Self {
            report: report.into(),
            failed: false,
            failure: None,
            partial_progress: DelegationPartialProgress::default(),
            child_routing: None,
        }
    }

    pub(in crate::engine::driver) fn failed(report: impl Into<String>) -> Self {
        Self {
            report: report.into(),
            failed: true,
            failure: None,
            partial_progress: DelegationPartialProgress::default(),
            child_routing: None,
        }
    }

    pub(in crate::engine::driver) fn failed_with_progress(
        report: impl Into<String>,
        partial_progress: DelegationPartialProgress,
    ) -> Self {
        let report = report.into();
        let report = render_failed_subagent_report(&report, &partial_progress);
        Self {
            report,
            failed: true,
            failure: None,
            partial_progress,
            child_routing: None,
        }
    }

    pub(in crate::engine::driver) fn failed_with_envelope(
        envelope: SubagentFailureEnvelope,
        partial_progress: DelegationPartialProgress,
    ) -> Self {
        let report = render_failed_subagent_failure(&envelope, &partial_progress);
        Self {
            report,
            failed: true,
            failure: Some(envelope),
            partial_progress,
            child_routing: None,
        }
    }

    pub(in crate::engine::driver) fn with_child_routing(
        mut self,
        child_routing: ChildRoutingMetadata,
    ) -> Self {
        self.child_routing = Some(child_routing);
        self
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(in crate::engine::driver) struct NoninteractiveDelegationEntry {
    pub(in crate::engine::driver) child_agent: String,
    pub(in crate::engine::driver) status: NoninteractiveDelegationStatus,
    pub(in crate::engine::driver) delivered: bool,
    pub(in crate::engine::driver) snapshot: NoninteractiveDelegationSnapshot,
    pub(in crate::engine::driver) steer_queue: std::collections::VecDeque<NoninteractiveSteer>,
    pub(in crate::engine::driver) completion: Option<NoninteractiveCompletionPayload>,
    /// Shared with the background execution driver's copy of this entry. The
    /// foreground driver owns completion/cancellation reconciliation, so it
    /// must observe a controlling stop gate emitted by the child before it
    /// decides whether an abnormal-path observe notification is still owed.
    pub(in crate::engine::driver) lifecycle: ChildHookLifecycle,
}

impl NoninteractiveDelegationEntry {
    pub(in crate::engine::driver) fn running(
        child_agent: String,
        snapshot: NoninteractiveDelegationSnapshot,
        lifecycle: ChildHookLifecycle,
    ) -> Self {
        Self {
            child_agent,
            status: NoninteractiveDelegationStatus::Running,
            delivered: false,
            snapshot,
            steer_queue: std::collections::VecDeque::new(),
            completion: None,
            lifecycle,
        }
    }
}

#[derive(Clone, Default)]
pub(in crate::engine::driver) struct NoninteractiveDelegationRegistry {
    pub(in crate::engine::driver) entries:
        std::collections::HashMap<NoninteractiveDelegationKey, NoninteractiveDelegationEntry>,
}

/// Session-local, parent-instance-scoped admission authority for vNext direct
/// children.  The key is the stable allocation identity of the parent `Arc<Agent>`:
/// clones of a driver used by background tasks retain that same parent frame, while
/// two independently-built agents with the same display name cannot consume one
/// another's child budget.
#[derive(Clone, Default)]
pub(in crate::engine::driver) struct VnextChildAdmissionRegistry {
    inner: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<usize, VnextChildAdmission>>>,
}

struct VnextChildAdmission {
    capacity: usize,
    permits: std::sync::Arc<tokio::sync::Semaphore>,
}

impl VnextChildAdmissionRegistry {
    /// Atomically reserve `children` live direct-child slots for this parent.
    /// A reservation is deliberately non-waiting: exceeding an agent's declared
    /// bound is a task-call refusal, not a queue whose eventual launch could
    /// surprise the parent after its turn has moved on.
    pub(in crate::engine::driver) fn try_admit(
        &self,
        parent: &std::sync::Arc<crate::engine::agent::Agent>,
        children: usize,
    ) -> std::result::Result<Vec<tokio::sync::OwnedSemaphorePermit>, String> {
        let Some(delegation) = parent
            .vnext_grant
            .as_ref()
            .and_then(|grant| grant.delegation.as_ref())
        else {
            return Ok(Vec::new());
        };
        let capacity = usize::from(delegation.max_concurrent_children);
        let key = std::sync::Arc::as_ptr(parent) as usize;
        self.try_admit_with_key(key, capacity, children).map_err(|()| {
            format!(
                "Error: `{}` has reached its vNext limit of {capacity} concurrent child task(s); wait for an active child to finish before delegating again",
                parent.name
            )
        })
    }

    fn try_admit_with_key(
        &self,
        key: usize,
        capacity: usize,
        children: usize,
    ) -> std::result::Result<Vec<tokio::sync::OwnedSemaphorePermit>, ()> {
        if children == 0 {
            return Ok(Vec::new());
        }
        let permits = {
            let mut admissions = self.inner.lock().expect("vNext admission lock poisoned");
            let admission = admissions
                .entry(key)
                .or_insert_with(|| VnextChildAdmission {
                    capacity,
                    permits: std::sync::Arc::new(tokio::sync::Semaphore::new(capacity)),
                });
            // A parent frame's effective grant is immutable. Treat a mismatch as
            // a refusal rather than accidentally widening an existing semaphore.
            if admission.capacity != capacity {
                return Err(());
            }
            admission.permits.clone()
        };

        let mut reservations = Vec::with_capacity(children);
        for _ in 0..children {
            match permits.clone().try_acquire_owned() {
                Ok(permit) => reservations.push(permit),
                Err(_) => return Err(()),
            }
        }
        Ok(reservations)
    }
}

#[allow(dead_code)]
impl NoninteractiveDelegationRegistry {
    #[cfg(test)]
    pub(in crate::engine::driver) fn register_running(
        &mut self,
        task_call_id: &str,
        label: &str,
        child_agent: String,
        snapshot: NoninteractiveDelegationSnapshot,
    ) {
        self.register_running_for_session(
            uuid::Uuid::nil(),
            task_call_id,
            label,
            child_agent,
            snapshot,
        );
    }

    pub(in crate::engine::driver) fn register_running_for_session(
        &mut self,
        session_id: uuid::Uuid,
        task_call_id: &str,
        label: &str,
        child_agent: String,
        snapshot: NoninteractiveDelegationSnapshot,
    ) {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        // The foreground registers before spawning its background driver. That
        // driver re-registers after preflight; retain the shared lifecycle latch
        // so stop-gate ownership crosses the clone boundary instead of becoming
        // private to whichever driver copy happened to run the child.
        let lifecycle = self
            .entries
            .get(&key)
            .map(|entry| entry.lifecycle.clone())
            .unwrap_or_else(|| {
                ChildHookLifecycle::already_started(
                    crate::db::task_delegations::delegation_child_lifecycle_id_for_session(
                        session_id,
                        task_call_id,
                        label,
                    ),
                )
            });
        self.entries.insert(
            key,
            NoninteractiveDelegationEntry::running(child_agent, snapshot, lifecycle),
        );
    }

    pub(in crate::engine::driver) fn set_snapshot(
        &mut self,
        task_call_id: &str,
        label: &str,
        snapshot: NoninteractiveDelegationSnapshot,
    ) {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.snapshot = snapshot;
        }
    }

    pub(in crate::engine::driver) fn child_hook_lifecycle(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Option<ChildHookLifecycle> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries.get(&key).map(|entry| entry.lifecycle.clone())
    }

    pub(in crate::engine::driver) fn push_steer(
        &mut self,
        task_call_id: &str,
        label: &str,
        body: String,
    ) {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.steer_queue.push_back(NoninteractiveSteer { body });
        }
    }

    pub(in crate::engine::driver) fn is_live(&self, task_call_id: &str, label: &str) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries.get(&key).is_some_and(|entry| {
            matches!(
                entry.status,
                NoninteractiveDelegationStatus::Running
                    | NoninteractiveDelegationStatus::Backgrounded
            )
        })
    }

    pub(in crate::engine::driver) fn cancel(&mut self, task_call_id: &str, label: &str) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if !matches!(
            entry.status,
            NoninteractiveDelegationStatus::Running | NoninteractiveDelegationStatus::Backgrounded
        ) {
            return false;
        }
        entry.status = NoninteractiveDelegationStatus::Cancelled;
        entry
            .completion
            .get_or_insert(NoninteractiveCompletionPayload {
                report: "cancelled".to_string(),
                failed: false,
                result: None,
            });
        true
    }

    pub(in crate::engine::driver) fn live_rows(
        &self,
    ) -> Vec<(
        String,
        String,
        String,
        NoninteractiveDelegationStatus,
        usize,
    )> {
        let mut rows = self
            .entries
            .iter()
            .map(|(key, entry)| {
                (
                    key.task_call_id.clone(),
                    key.label.clone(),
                    entry.child_agent.clone(),
                    entry.status,
                    entry.steer_queue.len(),
                )
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        rows
    }

    pub(in crate::engine::driver) fn snapshot_report(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Option<String> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let entry = self.entries.get(&key)?;
        if let Some(completion) = &entry.completion {
            return Some(completion.report.clone());
        }
        if entry.snapshot.history.is_empty() {
            return None;
        }
        let start = entry.snapshot.history.len().saturating_sub(6);
        serde_json::to_string(&entry.snapshot.history[start..]).ok()
    }

    pub(in crate::engine::driver) fn drain_steer_queue(
        &mut self,
        task_call_id: &str,
        label: &str,
    ) -> std::collections::VecDeque<NoninteractiveSteer> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries
            .get_mut(&key)
            .map(|entry| std::mem::take(&mut entry.steer_queue))
            .unwrap_or_default()
    }

    pub(in crate::engine::driver) fn background_on_user_input(
        &mut self,
        task_call_id: &str,
        label: &str,
    ) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if entry.status != NoninteractiveDelegationStatus::Running {
            return false;
        }
        entry.status = NoninteractiveDelegationStatus::Backgrounded;
        true
    }

    pub(in crate::engine::driver) fn complete(
        &mut self,
        task_call_id: &str,
        label: &str,
        report: String,
        failed: bool,
        result: Option<Message>,
    ) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if entry.completion.is_some() {
            return false;
        }
        entry.status = if failed {
            NoninteractiveDelegationStatus::Failed
        } else {
            NoninteractiveDelegationStatus::Completed
        };
        entry.completion = Some(NoninteractiveCompletionPayload {
            report,
            failed,
            result,
        });
        true
    }

    pub(in crate::engine::driver) fn completed_undelivered(
        &self,
        task_call_id: &str,
    ) -> Vec<(String, String)> {
        let mut rows = self
            .entries
            .iter()
            .filter(|(key, entry)| {
                key.task_call_id == task_call_id
                    && !entry.delivered
                    && matches!(
                        entry.status,
                        NoninteractiveDelegationStatus::Completed
                            | NoninteractiveDelegationStatus::Failed
                            | NoninteractiveDelegationStatus::Cancelled
                            | NoninteractiveDelegationStatus::Lost
                    )
            })
            .filter_map(|(key, entry)| {
                entry
                    .completion
                    .as_ref()
                    .map(|completion| (key.label.clone(), completion.report.clone()))
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    pub(in crate::engine::driver) fn running_labels(&self, task_call_id: &str) -> Vec<String> {
        let mut labels = self
            .entries
            .iter()
            .filter(|(key, entry)| {
                key.task_call_id == task_call_id
                    && matches!(
                        entry.status,
                        NoninteractiveDelegationStatus::Running
                            | NoninteractiveDelegationStatus::Backgrounded
                    )
            })
            .map(|(key, _)| key.label.clone())
            .collect::<Vec<_>>();
        labels.sort();
        labels
    }

    pub(in crate::engine::driver) fn is_backgrounded_job(&self, task_call_id: &str) -> bool {
        self.entries.iter().any(|(key, entry)| {
            key.task_call_id == task_call_id
                && entry.status == NoninteractiveDelegationStatus::Backgrounded
        })
    }

    pub(in crate::engine::driver) fn mark_delivered(
        &mut self,
        task_call_id: &str,
        label: &str,
    ) -> bool {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let Some(entry) = self.entries.get_mut(&key) else {
            return false;
        };
        if entry.delivered {
            return false;
        }
        entry.delivered = true;
        true
    }

    pub(in crate::engine::driver) fn take_late_result(
        &mut self,
        task_call_id: &str,
        label: &str,
    ) -> Option<Message> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        let result = self
            .entries
            .get(&key)
            .and_then(|entry| entry.completion.as_ref())
            .and_then(|completion| completion.result.clone())?;
        if !self.mark_delivered(task_call_id, label) {
            return None;
        }
        Some(result)
    }

    #[cfg(test)]
    pub(in crate::engine::driver) fn status(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Option<NoninteractiveDelegationStatus> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries.get(&key).map(|entry| entry.status)
    }

    #[cfg(test)]
    pub(in crate::engine::driver) fn child_agent(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Option<&str> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries
            .get(&key)
            .map(|entry| entry.child_agent.as_str())
    }

    #[cfg(test)]
    pub(in crate::engine::driver) fn snapshot_len(
        &self,
        task_call_id: &str,
        label: &str,
    ) -> Option<usize> {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries
            .get(&key)
            .map(|entry| entry.snapshot.history.len())
    }
}

pub(in crate::engine::driver) struct SingleNoninteractiveTask {
    pub(in crate::engine::driver) child_agent: String,
    pub(in crate::engine::driver) brief: String,
    pub(in crate::engine::driver) model:
        Option<crate::engine::model_roles::DelegationModelSelector>,
    pub(in crate::engine::driver) remaining_depth: Option<u32>,
    pub(in crate::engine::driver) why: String,
    pub(in crate::engine::driver) resume_handle: Option<String>,
    pub(in crate::engine::driver) child_cwd: ChildCwd,
    pub(in crate::engine::driver) context: crate::engine::agent::TaskContext,
    pub(in crate::engine::driver) write_scope: Option<String>,
    pub(in crate::engine::driver) granted_tools: Vec<String>,
    pub(in crate::engine::driver) todo_ids: Vec<uuid::Uuid>,
    pub(in crate::engine::driver) child_recursion:
        crate::engine::builtin::DelegationRecursionContext,
    pub(in crate::engine::driver) repair_notes: Vec<String>,
    pub(in crate::engine::driver) task_call_id: String,
    pub(in crate::engine::driver) task_provider_item_id: Option<String>,
    pub(in crate::engine::driver) task_function_call_id: Option<String>,
}

pub(in crate::engine::driver) struct SingleNoninteractiveCompletion {
    pub(in crate::engine::driver) child_agent: String,
    pub(in crate::engine::driver) task_call_id: String,
    pub(in crate::engine::driver) task_provider_item_id: Option<String>,
    pub(in crate::engine::driver) task_function_call_id: Option<String>,
    pub(in crate::engine::driver) report: String,
    pub(in crate::engine::driver) failed: bool,
    pub(in crate::engine::driver) failure: Option<SubagentFailureEnvelope>,
    pub(in crate::engine::driver) partial_progress: DelegationPartialProgress,
    pub(in crate::engine::driver) new_handle: Option<String>,
    pub(in crate::engine::driver) snapshot: NoninteractiveDelegationSnapshot,
    pub(in crate::engine::driver) shrink: Option<PendingDelegationShrink>,
    pub(in crate::engine::driver) repair_notes: Vec<String>,
    pub(in crate::engine::driver) child_routing: Option<ChildRoutingMetadata>,
}

pub(in crate::engine::driver) struct BatchNoninteractiveTask {
    pub(in crate::engine::driver) entries: Vec<crate::engine::agent::BatchTaskEntry>,
    pub(in crate::engine::driver) child_cwds: Vec<ChildCwd>,
    pub(in crate::engine::driver) why: String,
    pub(in crate::engine::driver) repair_notes: Vec<String>,
    pub(in crate::engine::driver) task_call_id: String,
    pub(in crate::engine::driver) task_provider_item_id: Option<String>,
    pub(in crate::engine::driver) task_function_call_id: Option<String>,
}

pub(in crate::engine::driver) struct BatchChildCompletion {
    pub(in crate::engine::driver) idx: usize,
    pub(in crate::engine::driver) label: String,
    pub(in crate::engine::driver) child_agent: String,
    pub(in crate::engine::driver) report: String,
    pub(in crate::engine::driver) failed: bool,
    pub(in crate::engine::driver) partial_progress: DelegationPartialProgress,
    pub(in crate::engine::driver) snapshot: NoninteractiveDelegationSnapshot,
}

pub(in crate::engine::driver) struct BatchNoninteractiveCompletion {
    pub(in crate::engine::driver) task_call_id: String,
    pub(in crate::engine::driver) task_provider_item_id: Option<String>,
    pub(in crate::engine::driver) task_function_call_id: Option<String>,
    pub(in crate::engine::driver) children: Vec<BatchChildCompletion>,
    pub(in crate::engine::driver) repair_notes: Vec<String>,
}

pub(in crate::engine::driver) enum BackgroundNoninteractiveCompletion {
    Single {
        task_call_id: String,
        task_provider_item_id: Option<String>,
        task_function_call_id: Option<String>,
        result: Box<Result<SingleNoninteractiveCompletion>>,
    },
    Batch {
        task_call_id: String,
        task_provider_item_id: Option<String>,
        task_function_call_id: Option<String>,
        result: Box<Result<BatchNoninteractiveCompletion>>,
    },
}

impl BackgroundNoninteractiveCompletion {
    pub(in crate::engine::driver) fn task_call_id(&self) -> &str {
        match self {
            Self::Single { task_call_id, .. } | Self::Batch { task_call_id, .. } => task_call_id,
        }
    }
}

pub(in crate::engine::driver) enum NoninteractiveCompletionDelivery {
    None,
    Inline(Message),
    AsyncUser(String),
}

impl NoninteractiveCompletionDelivery {
    pub(in crate::engine::driver) fn into_inline_message(self) -> Message {
        match self {
            Self::Inline(message) => message,
            Self::AsyncUser(text) => Message::user(text),
            Self::None => Message::user(""),
        }
    }
}

pub(in crate::engine::driver) struct BackgroundNoninteractiveJob {
    pub(in crate::engine::driver) delivered: bool,
    pub(in crate::engine::driver) handle: tokio::task::JoinHandle<()>,
    pub(in crate::engine::driver) cancel: tokio_util::sync::CancellationToken,
}

impl Drop for BackgroundNoninteractiveJob {
    fn drop(&mut self) {
        if !self.handle.is_finished() {
            self.cancel.cancel();
        }
    }
}

fn resolve_write_scope(
    scope: Option<&str>,
    base: &std::path::Path,
    workspace: &std::path::Path,
) -> Result<Option<std::path::PathBuf>, String> {
    let Some(scope) = scope.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let requested = crate::tools::common::resolve(scope, base);
    let effective = crate::path_containment::effective_path(&requested).map_err(|err| {
        format!(
            "`write_scope` `{}` cannot be resolved inside the workspace: {err}",
            requested.display()
        )
    })?;
    if !crate::path_containment::contained_under(workspace, &effective) {
        return Err(format!(
            "`write_scope` `{}` resolves outside the workspace `{}`",
            effective.display(),
            workspace.display()
        ));
    }
    Ok(Some(effective))
}

/// Resolve the next vNext structural child's requested cwd against the
/// current child's cwd, while retaining the session workspace boundary. The
/// effective-grant check that follows decides whether the real target is
/// same-root or a permitted subdirectory.
fn resolve_recursive_vnext_child_cwd(
    requested: Option<&str>,
    parent_cwd: &std::path::Path,
    workspace: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let parent = parent_cwd.canonicalize().map_err(|error| {
        format!(
            "could not resolve parent cwd `{}`: {error}",
            parent_cwd.display()
        )
    })?;
    let workspace = workspace.canonicalize().map_err(|error| {
        format!(
            "could not resolve trusted workspace `{}`: {error}",
            workspace.display()
        )
    })?;
    let Some(raw) = requested.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(parent);
    };
    let candidate = crate::tools::common::resolve(raw, &parent);
    let resolved = candidate
        .canonicalize()
        .map_err(|_| format!("cwd `{raw}` does not exist or is not a directory"))?;
    if !resolved.is_dir() {
        return Err(format!("cwd `{raw}` does not exist or is not a directory"));
    }
    if !crate::path_containment::contained_under(&workspace, &resolved) {
        return Err(format!(
            "cwd `{raw}` resolves outside trusted workspace `{}`",
            workspace.display()
        ));
    }
    Ok(resolved)
}

/// Recursive batches bypass the driver's durable completion queue, but their
/// parent-facing result keeps the exact same stable input-order contract as a
/// driver-owned batch. Completion order is deliberately not observable.
fn render_recursive_vnext_batch_result(
    mut reports: Vec<(usize, String, String, String)>,
) -> String {
    reports.sort_by_key(|(idx, _, _, _)| *idx);
    serde_json::json!({
        "status": "completed",
        "children": reports
            .into_iter()
            .map(|(_, label, child_agent, report)| serde_json::json!({
                "label": label,
                "agent": child_agent,
                "failed": report.starts_with("Error:"),
                "report": report,
            }))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

fn overlapping_write_scope_pair(
    scopes: &[(String, std::path::PathBuf)],
) -> Option<(String, std::path::PathBuf, String, std::path::PathBuf)> {
    for (idx, (left_label, left)) in scopes.iter().enumerate() {
        for (right_label, right) in scopes.iter().skip(idx + 1) {
            if crate::path_containment::contained_under(left, right)
                || crate::path_containment::contained_under(right, left)
            {
                return Some((
                    left_label.clone(),
                    left.clone(),
                    right_label.clone(),
                    right.clone(),
                ));
            }
        }
    }
    None
}

impl Driver {
    async fn pregrant_write_scope(&self, scope: &std::path::Path) {
        let Some(approver) = self.approver.as_ref() else {
            return;
        };
        if let Err(e) = approver
            .store()
            .record_path(
                scope,
                crate::approval::store::Scope::Session,
                crate::tools::shell_sandbox::SandboxPathAccess::ReadWrite,
            )
            .await
        {
            tracing::warn!(error = %e, scope = %scope.display(), "record scoped child write grant failed");
        }
    }

    #[cfg(test)]
    pub(in crate::engine::driver) async fn persist_delegation_payload(
        &self,
        task_call_id: &str,
        task_function_call_id: Option<&str>,
        parent_agent: &str,
        label: &str,
        child_agent: &str,
        prompt: &str,
    ) -> Result<String> {
        let prompt = prompt.to_string();
        self.session
            .db
            .insert_task_delegation_payload(
                crate::db::task_delegation_payloads::NewTaskDelegationPayload {
                    task_call_id,
                    function_call_id: task_function_call_id,
                    parent_session_id: self.session.id,
                    parent_agent,
                    label,
                    child_agent,
                    prompt: &prompt,
                },
            )
            .await
            .with_context(|| {
                format!("persisting task delegation payload `{task_call_id}:{label}`")
            })?;
        let loaded = self
            .session
            .db
            .load_task_delegation_payload(task_call_id, label)
            .await
            .with_context(|| format!("loading task delegation payload `{task_call_id}:{label}`"))?;
        Ok(loaded.body)
    }

    pub(in crate::engine::driver) async fn delegation_payload_delivery(
        &self,
        task_call_id: &str,
        label: &str,
        prompt: &str,
        retrieval_allowed: bool,
    ) -> Result<(Vec<Message>, String)> {
        let row = self
            .session
            .db
            .task_delegation_payload(task_call_id, label)
            .await?
            .with_context(|| format!("task delegation payload `{task_call_id}:{label}` missing"))?;
        if row.prompt_byte_len <= DELEGATION_PAYLOAD_DIRECT_LIMIT_BYTES {
            self.session
                .db
                .mark_task_delegation_payload_delivered(task_call_id, label)
                .await?;
            return Ok((Vec::new(), prompt.to_string()));
        }
        if !retrieval_allowed {
            bail!(DELEGATION_PAYLOAD_REFUSAL);
        }
        let history = delegation_payload_retrieval_history(&row, prompt);
        self.session
            .db
            .mark_task_delegation_payload_delivered(task_call_id, label)
            .await?;
        Ok((history, delegation_payload_reference_prompt(&row)))
    }

    pub(in crate::engine::driver) async fn current_message_fork_point(&self) -> Option<String> {
        match self.session.db.list_session_events(self.session.id).await {
            Ok(events) => events
                .into_iter()
                .rev()
                .find(|event| matches!(event.kind.as_str(), "user_message" | "assistant_message"))
                .map(|event| event.seq.to_string()),
            Err(e) => {
                tracing::warn!(error = %e, "load current message fork point failed");
                None
            }
        }
    }

    pub(in crate::engine::driver) async fn prepare_fork_task_context(
        &self,
    ) -> Result<(Arc<Session>, Vec<Message>)> {
        let history = self
            .stack
            .last()
            .expect("stack never empty")
            .history
            .clone();
        let fork_point = self.current_message_fork_point().await;
        let session = crate::session::Session::create_fork(
            self.session.db.clone(),
            self.session.id,
            fork_point,
            self.session.redaction_key_resolver().clone(),
            self.session.secret_vault().clone(),
        )
        .context("creating forked task session")?;
        session.set_external_journal(self.session.external_journal());
        // Inherit the parent's command-secret cache so the forked task session's
        // store funnel injects the same resolved command outputs (its
        // model/redaction/backup stores would otherwise resolve as missing).
        session.set_command_secret_cache(self.session.command_secret_cache());
        // Inherit the parent's descendant containment handle so the forked task
        // session's lifecycle hooks run their children under a proven lease (they
        // would otherwise get `None` and fail open as unsupported).
        session.set_process_containment(self.session.process_containment());
        Ok((Arc::new(session), history))
    }

    /// Validate a single-delegation child's execution surface from its OWN
    /// selected model, side-effect-free. Resolves the write scope and either the
    /// full child surface (ordinary child) or the EMBEDDED docs resolver-stage
    /// model (docs pipeline — the model the pipeline actually builds). Returns
    /// the content-safe routing error string on failure so a caller can fail
    /// closed BEFORE any task persist / registration / lifecycle mutation, and
    /// never falls back to the parent posture for a different selected model.
    fn preflight_single_delegation(
        &self,
        task: &SingleNoninteractiveTask,
    ) -> std::result::Result<(), String> {
        let scope = resolve_write_scope(
            task.write_scope.as_deref(),
            &task.child_cwd.resolved,
            &self.cwd,
        )
        .map_err(|e| format!("Error: {e}"))?;
        if task.child_agent == "docs" {
            let docs_args = self.spawn_args_delegated_in_cwd(
                &task.child_cwd.resolved,
                false,
                task.granted_tools.clone(),
                task.model.clone(),
                task.child_recursion.clone(),
            );
            crate::engine::builtin::resolve_child_model("docs-resolver", &docs_args)
                .map_err(|e| format!("Error: {e:#}"))?;
        } else {
            let args = self.spawn_args_delegated_in_cwd_scoped(
                &task.child_cwd.resolved,
                false,
                task.granted_tools.clone(),
                task.model.clone(),
                task.child_recursion.clone(),
                DelegationConfinement {
                    lock_identity: None,
                    write_scope: scope,
                },
            );
            crate::engine::builtin::resolve_child_execution_surface(&task.child_agent, &args)
                .map_err(|e| format!("Error: {e:#}"))?;
        }
        Ok(())
    }

    /// Validate ONE batch entry's child (or docs-stage) model, side-effect-free —
    /// the batch analogue of [`Self::preflight_single_delegation`]. Returns the
    /// content-safe routing error string on failure so the batch fails closed
    /// BEFORE persisting/registering any child.
    fn preflight_batch_entry(
        &self,
        entry: &crate::engine::agent::BatchTaskEntry,
        child_cwd: &ChildCwd,
    ) -> std::result::Result<(), String> {
        let child_recursion = self
            .resolve_task_recursion(&entry.child_agent, entry.remaining_depth, &entry.model)
            .map_err(|e| format!("Error: batch entry `{}`: {e}", entry.label))?;
        let scope =
            resolve_write_scope(entry.write_scope.as_deref(), &child_cwd.resolved, &self.cwd)
                .map_err(|e| format!("Error: batch entry `{}`: {e}", entry.label))?;
        if entry.child_agent == "docs" {
            let docs_args = self.spawn_args_delegated_in_cwd(
                &child_cwd.resolved,
                false,
                entry.granted_tools.clone(),
                entry.model.clone(),
                child_recursion,
            );
            crate::engine::builtin::resolve_child_model("docs-resolver", &docs_args)
                .map_err(|e| format!("Error: batch entry `{}`: {e:#}", entry.label))?;
        } else {
            let args = self.spawn_args_delegated_in_cwd_scoped(
                &child_cwd.resolved,
                false,
                entry.granted_tools.clone(),
                entry.model.clone(),
                child_recursion,
                DelegationConfinement {
                    lock_identity: None,
                    write_scope: scope,
                },
            );
            crate::engine::builtin::resolve_child_execution_surface(&entry.child_agent, &args)
                .map_err(|e| format!("Error: batch entry `{}`: {e:#}", entry.label))?;
        }
        Ok(())
    }

    /// Reserve live-child capacity at the sole task-launch authority. The
    /// returned permits must stay owned by the spawned task/frame until each
    /// child exits; dropping them is the release path for success, refusal,
    /// cancellation, and panic alike.
    pub(super) fn admit_current_vnext_children(
        &self,
        children: usize,
    ) -> std::result::Result<Vec<tokio::sync::OwnedSemaphorePermit>, String> {
        self.vnext_child_admissions.try_admit(
            &self.stack.last().expect("stack never empty").agent,
            children,
        )
    }

    pub(in crate::engine::driver) async fn run_single_noninteractive_task_backgroundable(
        &mut self,
        mut task: SingleNoninteractiveTask,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Message> {
        // FAIL CLOSED before ANY task persist / registration / lifecycle mutation:
        // validate the child's execution surface from its OWN selected model. An
        // unresolvable child model (or docs-stage model) returns the content-safe
        // routing error having persisted no task delegation, registered no running
        // child, spawned nothing, and dispatched no inference.
        if let Err(err) = self.preflight_single_delegation(&task) {
            return Ok(
                crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                    task.task_call_id.clone(),
                    task.task_provider_item_id.clone(),
                    task.task_function_call_id.clone(),
                    "task",
                    prepend_task_repair_notes(err, &task.repair_notes),
                ),
            );
        }
        let vnext_admissions = match self.admit_current_vnext_children(1) {
            Ok(permits) => permits,
            Err(err) => {
                return Ok(
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task.task_call_id.clone(),
                        task.task_provider_item_id.clone(),
                        task.task_function_call_id.clone(),
                        "task",
                        prepend_task_repair_notes(err, &task.repair_notes),
                    ),
                );
            }
        };
        let task_call_id = task.task_call_id.clone();
        let task_provider_item_id = task.task_provider_item_id.clone();
        let task_function_call_id = task.task_function_call_id.clone();
        let resolved_cwd_display = task.child_cwd.resolved_display();
        let task_args_json = serde_json::to_string(&serde_json::json!({
            "child_agent": &task.child_agent,
            "model": model_selector_json(&task.model),
            "why": &task.why,
            "resume_handle": &task.resume_handle,
            "context": task.context.as_str(),
            "requested_cwd": task.child_cwd.requested_json(),
            "resolved_cwd": &resolved_cwd_display,
            "write_scope": &task.write_scope,
            "todo_ids": &task.todo_ids,
        }))
        .ok();
        let parent_agent = self.stack.last().unwrap().agent.name.clone();
        let model_display = model_selector_display(&task.model);
        let child_inits = [crate::db::task_delegations::DelegationChildInit {
            label: "default",
            child_agent: &task.child_agent,
            model: model_display.as_deref(),
            output_dir: task.write_scope.as_deref(),
            requested_cwd: task.child_cwd.requested_json(),
            resolved_cwd: Some(&resolved_cwd_display),
            todo_ids_json: None,
        }];
        match self
            .session
            .db
            .upsert_task_delegation_job_and_payload(
                crate::db::task_delegations::TaskDelegationJobUpsert {
                    session_id: self.session.id,
                    task_call_id: &task_call_id,
                    function_call_id: task_function_call_id.as_deref(),
                    parent_agent: &parent_agent,
                    original_args_json: task_args_json.as_deref(),
                    children: &child_inits,
                },
                crate::db::task_delegation_payloads::NewTaskDelegationPayload {
                    task_call_id: &task_call_id,
                    function_call_id: task_function_call_id.as_deref(),
                    parent_session_id: self.session.id,
                    parent_agent: &parent_agent,
                    label: "default",
                    child_agent: &task.child_agent,
                    prompt: &task.brief,
                },
            )
            .await
        {
            Ok(row) => {
                if task.context == crate::engine::agent::TaskContext::Fresh {
                    task.brief = delegation_payload_reference_prompt(&row);
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "persist single task delegation job and payload failed");
                return Ok(
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "task",
                        prepend_task_repair_notes(
                            DELEGATION_PAYLOAD_REFUSAL.to_string(),
                            &task.repair_notes,
                        ),
                    ),
                );
            }
        }
        self.noninteractive_delegations.register_running_for_session(
            self.session.id,
            &task_call_id,
            "default",
            task.child_agent.clone(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        // `subagentStart` observe hook: the NONINTERACTIVE (background delegation)
        // child is now registered running — the durable job/payload persisted and
        // every pre-spawn refusal (`preflight_single_delegation`, the payload
        // upsert failure above) already returned WITHOUT reaching here, so this
        // fires only for a child that actually starts. Child-only; matcher /
        // `subagentType` is the child agent type, `subagentId` is the delegating
        // `task` call id. Paired with exactly one `subagentStop` at delegation
        // delivery (`finalize_background_noninteractive_completion`).
        let child_lifecycle_id =
            crate::db::task_delegations::delegation_child_lifecycle_id_for_session(
                self.session.id,
                &task_call_id,
                "default",
            );
        self.fire_subagent_hook(&task.child_agent, Some(&child_lifecycle_id))
        .await;
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let completion_task_call_id = task_call_id.clone();
        let completion_task_provider_item_id = task_provider_item_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
        let job_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            // Keep the reservation alive for the full background child
            // lifetime, including time spent after the foreground has moved on.
            let _vnext_admissions = vnext_admissions;
            let result = runner
                .execute_single_noninteractive_task(task, &tx_for_task, cancel)
                .await;
            let _ = complete_tx
                .send(BackgroundNoninteractiveCompletion::Single {
                    task_call_id: completion_task_call_id,
                    task_provider_item_id: completion_task_provider_item_id,
                    task_function_call_id: completion_task_function_call_id,
                    result: Box::new(result),
                })
                .await;
        });
        self.noninteractive_jobs.insert(
            task_call_id.clone(),
            BackgroundNoninteractiveJob {
                delivered: false,
                handle,
                cancel: job_cancel,
            },
        );
        tokio::select! {
            biased;
            user = input_rx.recv() => {
                let Some(first) = user else {
                    return Ok(Message::user(""));
                };
                let queue_item_ids = first.queue_item_ids.clone();
                if self
                    .requeue_command_submission_for_boundary(input_rx, first.clone())
                    .await
                {
                    let completion = self.recv_noninteractive_completion_for(&task_call_id).await;
                    let delivery = self
                        .finalize_background_noninteractive_completion(completion, tx)
                        .await?;
                    self.reap_finished_noninteractive_jobs();
                    return Ok(delivery.into_inline_message());
                }
                self.noninteractive_delegations
                    .background_on_user_input(&task_call_id, "default");
                if let Err(e) = self
                    .session
                    .db
                    .background_task_delegation_child(&task_call_id, "default")
                    .await
                {
                    tracing::warn!(error = %e, task_call_id, "background single task delegation failed");
                }
                let ack = self
                    .background_delegation_ack(
                        &task_call_id,
                        task_provider_item_id.clone(),
                        task_function_call_id.clone(),
                    )
                    .await;
                if let Some(parent) = self.stack.last_mut() {
                    parent.history.push(ack);
                }
                let Some(prepared) = self
                    .prepare_queued_user_submission(first, input_rx, tx)
                    .await
                else {
                    input_rx.finish(&queue_item_ids).await;
                    return Ok(Message::user(""));
                };
                if self.record_queued_user_fold(&prepared, tx).await.is_err() {
                    input_rx
                        .requeue_front_after(
                            prepared,
                            self.active_queue_target(),
                            DURABLE_SUBMISSION_RETRY_BACKOFF,
                        )
                        .await;
                    return Ok(Message::user(""));
                }
                input_rx.finish(&queue_item_ids).await;
                Ok(crate::engine::message::build_user_message(UserSubmission {
                    origin: crate::engine::message::SubmissionOrigin::ExternalRoot,
                    expected_model_state_generation: None,
                    expected_model: None,
                    kind: UserSubmissionKind::User,
                    text: self.with_time_prelude(prepared.text),
                    display_text: None,
                    tag_expansions: Vec::new(),
                    images: prepared.images,
                    forced_skill: None,
                    origin_principal: None,
                    job_id: None,
                    preflight_cleaned: None,
                    queue_item_ids: Vec::new(),
                    client_submissions: Vec::new(),
                    queue_target: None,
                    pending_terminal_disposition: None,
                    run_invocation_id: None,
                }))
            }
            completion = self.recv_noninteractive_completion_for(&task_call_id) => {
                let delivery = self
                    .finalize_background_noninteractive_completion(completion, tx)
                    .await?;
                self.reap_finished_noninteractive_jobs();
                Ok(delivery.into_inline_message())
            }
        }
    }

    pub(in crate::engine::driver) async fn execute_single_noninteractive_task(
        &mut self,
        task: SingleNoninteractiveTask,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<SingleNoninteractiveCompletion> {
        let SingleNoninteractiveTask {
            child_agent,
            brief,
            model,
            remaining_depth,
            why,
            resume_handle,
            child_cwd,
            context,
            write_scope,
            granted_tools,
            todo_ids,
            child_recursion,
            repair_notes,
            task_call_id,
            task_provider_item_id,
            task_function_call_id,
        } = task;

        // Repin the config to a held snapshot for THIS delegation attempt. A
        // pinned handle's reads return the fixed snapshot and do NOT observe later
        // live refreshes, so every read below — child model resolution, posture
        // (`child_llm_mode_for_model`), surface, handoff-tag expansion,
        // `pregrant_write_scope`, `builtin::load`/build, dispatch, and the docs
        // pipeline's internal `spawn_args.config` reads — sees ONE generation. The
        // child's identity AND posture come from the pinned generation by
        // construction (AC6), a concurrent refresh affects only the NEXT
        // delegation, and the write-scope grant cannot be orphaned by a move
        // because the config physically cannot move mid-attempt.
        self.config = self.config.repin();

        // FAIL CLOSED before ANY child lifecycle / spawn side effect. Resolve the
        // write scope and the child's execution surface from its OWN selected
        // model FIRST: an invalid write scope or an unresolvable child model
        // returns the content-safe routing error having registered NO running
        // delegation, emitted/journaled NO `SubagentSpawned` event, begun NO
        // delegation-shrink, and pregranted NO write scope. `llm_mode` is the
        // child's OWN resolved posture — never a parent-frame fallback for a
        // different selected model; `docs` resolves its posture from the model its
        // stages actually build under (`docs-resolver`).
        let resolved_write_scope =
            match resolve_write_scope(write_scope.as_deref(), &child_cwd.resolved, &self.cwd) {
                Ok(scope) => scope,
                Err(err) => {
                    return Ok(SingleNoninteractiveCompletion {
                        child_agent,
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        report: format!("Error: {err}"),
                        failed: true,
                        failure: None,
                        partial_progress: DelegationPartialProgress::default(),
                        new_handle: None,
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                        shrink: None,
                        repair_notes,
                        child_routing: None,
                    });
                }
            };
        // Check reachability before resolving the child's execution surface.
        // Surface resolution intentionally reads the child configuration from
        // the selected cwd, but an unknown child must retain the parent-facing
        // diagnostic (including the reachable-agent list) and must not reach a
        // loader.  This is also the last point before any delegation state is
        // registered, so a refusal has no child lifecycle side effect.
        let parent_agent = self.stack.last().unwrap().agent.name.clone();
        let parent_vnext_grant = self
            .stack
            .last()
            .and_then(|frame| frame.agent.vnext_grant.clone());
        if let Some(err) = grant_rejection(GrantRejectionInput {
            parent_cwd: &self.cwd,
            cwd: &child_cwd.resolved,
            config: &self.config,
            parent_agent: &parent_agent,
            parent_vnext_grant: parent_vnext_grant.as_ref(),
            child_agent: &child_agent,
            grant: &granted_tools,
            assistant_db: &self.session.db,
            local_installations: &self.vnext_local_installation_resolver,
        })
        .await
        {
            return Ok(SingleNoninteractiveCompletion {
                child_agent,
                task_call_id,
                task_provider_item_id,
                task_function_call_id,
                report: err,
                failed: true,
                failure: None,
                partial_progress: DelegationPartialProgress::default(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: None,
                repair_notes,
                child_routing: None,
            });
        }
        // The child's posture is derived from the pinned attempt config, so the
        // `llm_mode` here (→ follow-up/child-only capability) and the handoff-tag
        // expansion below share the SAME generation as the later build/dispatch —
        // no split is possible.
        let llm_mode = if child_agent == "docs" {
            // The `docs` pipeline builds its EMBEDDED resolver/answerer stages from
            // that stage model, so validate its resolvability here and FAIL CLOSED
            // — never substitute the parent posture. (The pinned attempt config
            // guarantees the pipeline's stages resolve under this same generation.)
            let docs_args = self.spawn_args_delegated_in_cwd(
                &child_cwd.resolved,
                false,
                granted_tools.clone(),
                model.clone(),
                child_recursion.clone(),
            );
            match crate::engine::builtin::resolve_child_model("docs-resolver", &docs_args) {
                Ok(docs_model) => {
                    crate::engine::builtin::child_llm_mode_for_model(&docs_args, &docs_model)
                }
                Err(e) => {
                    return Ok(SingleNoninteractiveCompletion {
                        child_agent,
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        report: format!("Error: {e:#}"),
                        failed: true,
                        failure: None,
                        partial_progress: DelegationPartialProgress::default(),
                        new_handle: None,
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                        shrink: None,
                        repair_notes,
                        child_routing: None,
                    });
                }
            }
        } else {
            let preflight_args = self.spawn_args_delegated_in_cwd_scoped(
                &child_cwd.resolved,
                false,
                granted_tools.clone(),
                model.clone(),
                child_recursion.clone(),
                DelegationConfinement {
                    lock_identity: None,
                    write_scope: resolved_write_scope.clone(),
                },
            );
            match crate::engine::builtin::resolve_child_execution_surface(
                &child_agent,
                &preflight_args,
            ) {
                Ok(surface) => surface.llm_mode,
                Err(e) => {
                    return Ok(SingleNoninteractiveCompletion {
                        child_agent,
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        report: format!("Error: {e:#}"),
                        failed: true,
                        failure: None,
                        partial_progress: DelegationPartialProgress::default(),
                        new_handle: None,
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                        shrink: None,
                        repair_notes,
                        child_routing: None,
                    });
                }
            }
        };
        let followup_enabled = crate::engine::tool::Capability::FollowupSeed.enabled(llm_mode);

        self.noninteractive_delegations.register_running_for_session(
            self.session.id,
            &task_call_id,
            "default",
            child_agent.clone(),
            NoninteractiveDelegationSnapshot::empty(),
        );

        let (delegation_payload_history, delivered_brief) = if context
            == crate::engine::agent::TaskContext::Fork
        {
            (Vec::new(), brief.clone())
        } else {
            match self
                .delegation_payload_delivery(
                    &task_call_id,
                    "default",
                    &brief,
                    child_agent != "docs",
                )
                .await
            {
                Ok(delivery) => delivery,
                Err(e) => {
                    tracing::warn!(error = %e, task_call_id, "task delegation payload delivery failed");
                    return Ok(SingleNoninteractiveCompletion {
                        child_agent,
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        report: DELEGATION_PAYLOAD_REFUSAL.to_string(),
                        failed: true,
                        failure: None,
                        partial_progress: DelegationPartialProgress::default(),
                        new_handle: None,
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                        shrink: None,
                        repair_notes,
                        child_routing: None,
                    });
                }
            }
        };

        let routing = self
            .stack
            .last()
            .unwrap()
            .agent
            .model
            .routing_metadata_json(None);
        let _ = tx
            .send(TurnEvent::SubagentSpawned {
                parent: self.stack.last().unwrap().agent.name.clone(),
                child: child_agent.clone(),
                task_call_id: task_call_id.clone(),
                label: "default".to_string(),
                prompt: delivered_brief.clone(),
                requested_cwd: child_cwd.requested.clone(),
                resolved_cwd: Some(child_cwd.resolved_display()),
                model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                routing: routing.clone(),
            })
            .await;
        let task_identity = crate::engine::task_identity::TaskProviderIdentity::for_task_call(
            &task_call_id,
            task_provider_item_id.as_deref(),
            task_function_call_id.as_deref(),
        );
        // This event embeds the parent model's task `prompt` (model-authored
        // free text that can carry a session-table literal), so route it through
        // the frame-carrying journaling path with the SPAWNING model's trust +
        // pre-policy session table (mirrors the SubagentReport fix). A frame-less
        // `record_event` skips the trusted journaling branch entirely, so a
        // session-table literal in a trusted parent's prompt would persist raw
        // with no history row; an untrusted spawning model journals nothing (its
        // payload is already post-redaction). The spawning model is
        // `self.stack.last().unwrap().agent.model`; `self.redact` is the
        // session's pre-policy table (as the SubagentReport fix used).
        if let Err(e) = self
            .session
            .record_event_with_model_frame(
                crate::db::session_log::SessionEventKind::SubagentSpawned,
                Some(&self.stack.last().unwrap().agent.name),
                Some(&task_call_id),
                crate::session::SessionEventModelFrame {
                    provider_id: self.stack.last().unwrap().agent.model.provider_id(),
                    model_id: self.stack.last().unwrap().agent.model.model_id_ref(),
                    config: &self.config,
                    session_table: self.redact.as_ref(),
                },
                &serde_json::json!({
                    "child_agent": child_agent.clone(),
                    "task_call_id": task_call_id,
                    "provider_item_id": task_identity.provider_item_id,
                    "provider_call_id": task_identity.provider_call_id,
                    "provider_call_id_source": task_identity.provider_call_id_source,
                    "provider_identity": task_identity.event_identity_json(&task_call_id),
                    "label": "default",
                    "noninteractive": true,
                    "prompt": delivered_brief.clone(),
                    "why": why.clone(),
                    "model": model_selector_json(&model),
                    "model_trusted": self.stack.last().unwrap().agent.model.is_trusted(),
                    "routing": routing,
                    "context": context.as_str(),
                    "remaining_depth": remaining_depth,
                    "resume_handle": resume_handle.clone(),
                    "requested_cwd": child_cwd.requested_json(),
                    "resolved_cwd": child_cwd.resolved_display(),
                    "write_scope": write_scope.clone(),
                    "grant_tools": granted_tools.clone(),
                    "todo_ids": todo_ids.clone(),
                }),
            )
            .await
        {
            tracing::warn!(error = %e, "record single subagent_spawned event failed");
        }

        let parent_full = self
            .stack
            .last()
            .expect("stack never empty")
            .history
            .clone();
        let (tracker, shrink_handle) = self.begin_delegation_shrink(parent_full);

        // NOTE: `pregrant_write_scope` is DEFERRED to each branch's dispatch point,
        // AFTER that branch's final generation-consistency check (docs / non-docs
        // below), so a generation move never records a lingering write-scope grant.
        let mut child_session = self.session.clone();
        let mut fork_prior_history = Vec::new();
        if context == crate::engine::agent::TaskContext::Fork {
            match self.prepare_fork_task_context().await {
                Ok((session, history)) => {
                    child_session = session;
                    fork_prior_history = history;
                }
                Err(e) => {
                    return Ok(SingleNoninteractiveCompletion {
                        child_agent,
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        report: format!("Error: failed to create forked task session: {e:#}"),
                        failed: true,
                        failure: None,
                        partial_progress: DelegationPartialProgress::default(),
                        new_handle: None,
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                        shrink: Some(PendingDelegationShrink {
                            tracker,
                            handle: shrink_handle,
                        }),
                        repair_notes,
                        child_routing: None,
                    });
                }
            }
        }
        let composed_brief = if context == crate::engine::agent::TaskContext::Fork {
            delivered_brief.clone()
        } else {
            compose_subagent_brief(&delivered_brief, &why)
        };
        let mut new_handle: Option<String> = None;
        let mut snapshot = NoninteractiveDelegationSnapshot::empty();
        let composed_brief = self
            .assign_todos_to_task(
                composed_brief,
                &todo_ids,
                &task_call_id,
                "default",
                &child_agent,
            )
            .await;
        let composed_brief =
            self.expand_handoff_tags(&composed_brief, &child_cwd.resolved, llm_mode, &child_agent);

        let outcome = if child_agent == "docs" {
            // The docs pipeline is not a built-in child agent load, so there is
            // no resolved child model to amend onto the earlier spawn event (no
            // routing amend is emitted). The pipeline DOES return the model that
            // authored the report, which we attach as `child_routing` below so
            // the finalizer journals the report through the frame-carrying path
            // (decision 10.3) instead of the frame-less `record_event` — a
            // trusted docs report with a session-table literal must journal /
            // fail-closed scrub, not persist raw.
            if resume_handle.is_some() {
                DelegationChildOutcome::failed(stale_handle_error(&child_agent))
            } else {
                // The pinned attempt config makes the pipeline's stages
                // generation-consistent with this handoff; record the write-scope
                // grant (it cannot be orphaned — the config cannot move).
                if let Some(scope) = resolved_write_scope.as_ref() {
                    self.pregrant_write_scope(scope).await;
                }
                match crate::engine::docs_pipeline::run(
                    &composed_brief,
                    &self.spawn_args_delegated_in_cwd(
                        &child_cwd.resolved,
                        false,
                        Vec::new(),
                        model.clone(),
                        child_recursion.clone(),
                    ),
                    self.session.clone(),
                    self.locks.clone(),
                    self.redact.clone(),
                    self.config.clone(),
                    self.approver.clone(),
                    self.interrupts.clone(),
                    cancel.clone(),
                    Some(self.tandem_set.clone()),
                    Some(tx.clone()),
                    Some(NoninteractiveSteerTarget::new(
                        task_call_id.clone(),
                        "default",
                    )),
                )
                .await
                {
                    Ok(report) => DelegationChildOutcome::ok(report.report).with_child_routing(
                        ChildRoutingMetadata::from_model(report.report_model.as_ref()),
                    ),
                    Err(e) => DelegationChildOutcome::failed(format!("Error: {e:#}")),
                }
            }
        } else {
            let rehydrated = match &resume_handle {
                None => Ok(Vec::new()),
                Some(handle) => {
                    self.rehydrate_handle(
                        handle,
                        &child_agent,
                        Some(&child_cwd.resolved),
                        followup_enabled,
                    )
                    .await
                }
            };
            match rehydrated {
                Err(msg) => DelegationChildOutcome::failed(msg),
                Ok(prior_history) => {
                    let child = match crate::engine::builtin::load(
                        &child_agent,
                        &self.spawn_args_delegated_in_cwd_scoped(
                            &child_cwd.resolved,
                            false,
                            granted_tools.clone(),
                            model.clone(),
                            child_recursion.clone(),
                            DelegationConfinement {
                                lock_identity: None,
                                write_scope: resolved_write_scope.clone(),
                            },
                        ),
                    ) {
                        Ok(child) => child,
                        Err(e) => {
                            return Ok(SingleNoninteractiveCompletion {
                                child_agent,
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                report: format!("Error: {e:#}"),
                                failed: true,
                                failure: None,
                                partial_progress: DelegationPartialProgress::default(),
                                new_handle: None,
                                snapshot: NoninteractiveDelegationSnapshot::empty(),
                                shrink: Some(PendingDelegationShrink {
                                    tracker,
                                    handle: shrink_handle,
                                }),
                                repair_notes,
                                child_routing: None,
                            });
                        }
                    };
                    // The child was BUILT from the pinned attempt config, so its
                    // model + posture match the `llm_mode`/handoff derived above by
                    // construction — no generation split is possible. Record the
                    // write-scope grant (it cannot be orphaned by a move).
                    if let Some(scope) = resolved_write_scope.as_ref() {
                        self.pregrant_write_scope(scope).await;
                    }
                    let child_routing = ChildRoutingMetadata::from_model(&child.model);
                    self.emit_subagent_routing_amend(
                        tx,
                        &child_agent,
                        &task_call_id,
                        "default",
                        &child_routing,
                    )
                    .await;
                    let write_capable = crate::engine::builtin::is_write_capable(&child);
                    if resume_handle.is_some() && write_capable {
                        match self.locks.resume_agent(&child_agent, self.session.id).await {
                            Ok(reacquired) => {
                                tracing::debug!(
                                    agent = %child_agent,
                                    reacquired = reacquired.len(),
                                    "followup resume reacquired locks hash-matched"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(error = ?e, agent = %child_agent, "followup resume_agent failed");
                            }
                        }
                    }
                    if resume_handle.is_some() {
                        let reuse = self.followup_reuse_decision();
                        // Metadata-only SubagentSpawned: this payload carries no
                        // model-authored free text (only `followup_resume`,
                        // `reuse_decision`, and `write_capable`), so it needs no
                        // model frame — plain `record_event` is correct here.
                        if let Err(e) = self
                            .session
                            .record_event(
                                crate::db::session_log::SessionEventKind::SubagentSpawned,
                                Some(&child_agent),
                                Some(&task_call_id),
                                &serde_json::json!({
                                    "followup_resume": true,
                                    "reuse_decision": format!("{reuse:?}"),
                                    "write_capable": write_capable,
                                }),
                            )
                            .await
                        {
                            tracing::warn!(error = %e, "record followup reuse event failed");
                        }
                    }
                    let mut prior_history = if context == crate::engine::agent::TaskContext::Fork {
                        fork_prior_history.clone()
                    } else {
                        prior_history
                    };
                    let mut delivery_history = delegation_payload_history.clone();
                    if context != crate::engine::agent::TaskContext::Fork
                        && !delivery_history.is_empty()
                    {
                        delivery_history.append(&mut prior_history);
                        prior_history = delivery_history;
                    }
                    // Render the assembled brief for the child's resolved
                    // custody class before dispatch, exactly as the batch path
                    // does. Untrusted (cloud) children get the session
                    // redaction-table rendering; trusted (self-hosted / no-log)
                    // children get it unchanged.
                    let dispatch_brief = {
                        let (extended, providers) =
                            crate::engine::model_roles::load_model_role_config(&self.config);
                        crate::engine::model_roles::render_brief_for_model(
                            &providers,
                            &child.model,
                            &extended,
                            &composed_brief,
                        )
                    };
                    let child_hook_lifecycle = self
                        .noninteractive_delegations
                        .child_hook_lifecycle(&task_call_id, "default")
                        .expect("single child lifecycle registered before execution");
                    let child_result = run_noninteractive_resumable(
                        child,
                        dispatch_brief,
                        prior_history,
                        child_session.clone(),
                        self.locks.clone(),
                        self.redact.clone(),
                        child_cwd.resolved.clone(),
                        self.config.clone(),
                        self.process_containment.clone(),
                        Some(child_hook_lifecycle.clone()),
                        self.interrupts.clone(),
                        cancel,
                        self.approver.clone(),
                        self.resource_scheduler.clone(),
                        self.loop_guard_threshold,
                        EXPLORE_MAX_TURNS,
                        self.vnext_local_installation_resolver.clone(),
                        Some(self.tandem_set.clone()),
                        Some(tx.clone()),
                        Some(NoninteractiveSteerTarget::new(
                            task_call_id.clone(),
                            "default",
                        )),
                    )
                    .await;
                    match child_result {
                        Err(e) => {
                            let (message, history, fallback_decision, failure_envelope) =
                                e.into_parts();
                            let partial_progress = partial_progress_from_history(&history);
                            snapshot = NoninteractiveDelegationSnapshot::from_history(history);
                            let final_child_routing = child_routing
                                .clone()
                                .with_fallback_decision(fallback_decision.as_ref());
                            if fallback_decision.is_some() {
                                self.emit_subagent_routing_amend(
                                    tx,
                                    &child_agent,
                                    &task_call_id,
                                    "default",
                                    &final_child_routing,
                                )
                                .await;
                            }
                            let outcome = match failure_envelope {
                                Some(envelope) => DelegationChildOutcome::failed_with_envelope(
                                    envelope,
                                    partial_progress,
                                ),
                                None => DelegationChildOutcome::failed_with_progress(
                                    format!("Error: {message}"),
                                    partial_progress,
                                ),
                            };
                            outcome.with_child_routing(final_child_routing)
                        }
                        Ok(outcome) => {
                            snapshot = NoninteractiveDelegationSnapshot::from_history(
                                outcome.history.clone(),
                            );
                            let final_child_routing = child_routing
                                .clone()
                                .with_fallback_decision(outcome.fallback_decision.as_ref());
                            if outcome.fallback_decision.is_some() {
                                self.emit_subagent_routing_amend(
                                    tx,
                                    &child_agent,
                                    &task_call_id,
                                    "default",
                                    &final_child_routing,
                                )
                                .await;
                            }
                            if followup_enabled
                                && crate::engine::builtin::is_followup_eligible(&child_agent)
                            {
                                new_handle = self
                                    .persist_subagent_handle(
                                        &child_agent,
                                        &outcome.history,
                                        Some(&child_cwd.resolved),
                                        resume_handle.as_deref(),
                                    )
                                    .await;
                                if write_capable
                                    && let Err(e) = self
                                        .locks
                                        .suspend_agent(&child_agent, self.session.id)
                                        .await
                                {
                                    tracing::warn!(error = ?e, agent = %child_agent, "followup suspend_agent at finish failed");
                                }
                            }
                            DelegationChildOutcome::ok(outcome.report)
                                .with_child_routing(final_child_routing)
                        }
                    }
                }
            }
        };

        Ok(SingleNoninteractiveCompletion {
            child_agent,
            task_call_id,
            task_provider_item_id,
            task_function_call_id,
            report: outcome.report,
            failed: outcome.failed,
            failure: outcome.failure,
            partial_progress: outcome.partial_progress,
            new_handle,
            snapshot,
            shrink: Some(PendingDelegationShrink {
                tracker,
                handle: shrink_handle,
            }),
            repair_notes,
            child_routing: outcome.child_routing,
        })
    }

    pub(in crate::engine::driver) async fn finalize_single_noninteractive_task(
        &mut self,
        completion: SingleNoninteractiveCompletion,
        tx: &mpsc::Sender<TurnEvent>,
        apply_shrink: bool,
    ) -> Result<Message> {
        let SingleNoninteractiveCompletion {
            child_agent,
            task_call_id,
            task_provider_item_id,
            task_function_call_id,
            report,
            failed,
            failure,
            partial_progress,
            new_handle,
            snapshot,
            shrink,
            repair_notes,
            child_routing,
        } = completion;

        let emit_report_event = shrink.is_some();
        if !emit_report_event {
            let report = prepend_task_repair_notes(report, &repair_notes);
            let report = self
                .maybe_scan_task_report(&child_agent, report, tx)
                .await?;
            let caller = self.stack.last().expect("stack never empty").agent.clone();
            let report =
                self.expand_handoff_tags(&report, &self.cwd, caller.llm_mode, &caller.name);
            let result =
                crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                    task_call_id.clone(),
                    task_provider_item_id,
                    task_function_call_id,
                    "task",
                    report.clone(),
                );
            self.noninteractive_delegations
                .set_snapshot(&task_call_id, "default", snapshot);
            self.noninteractive_delegations.complete(
                &task_call_id,
                "default",
                report.clone(),
                failed,
                Some(result.clone()),
            );
            if let Err(e) = self
                .session
                .db
                .complete_task_delegation_child(&task_call_id, "default", &report, failed, None)
                .await
            {
                tracing::warn!(error = %e, task_call_id, "complete single delegation child failed");
            }
            let _ = self
                .noninteractive_delegations
                .mark_delivered(&task_call_id, "default");
            return Ok(result);
        }
        if apply_shrink {
            if let Some(PendingDelegationShrink { tracker, handle }) = shrink {
                self.finish_delegation_shrink(tracker, handle, tx).await;
            }
        } else {
            Self::discard_delegation_shrink(shrink);
        }

        let report = self
            .reconcile_todo_delta(&task_call_id, "default", &child_agent, &report, failed)
            .await;
        let report = match &new_handle {
            Some(handle) => format!("{report}{}", handle_footer(handle)),
            None => report,
        };
        let report = prepend_task_repair_notes(report, &repair_notes);
        let report = self
            .maybe_scan_task_report(&child_agent, report, tx)
            .await?;
        let caller = self.stack.last().expect("stack never empty").agent.clone();
        let report = self.expand_handoff_tags(&report, &self.cwd, caller.llm_mode, &caller.name);

        let mut report_data = subagent_report_event_data(
            &child_agent,
            Some(&task_call_id),
            task_provider_item_id.as_deref(),
            task_function_call_id.as_deref(),
            "default",
            &report,
            Some(&partial_progress),
        );
        if let Some(files_touched) = extract_files_touched(&report) {
            report_data["files_touched"] = serde_json::to_value(files_touched)
                .unwrap_or_else(|_| serde_json::json!({ "serialization_error": true }));
        }
        if let Some(failure) = failure.as_ref() {
            report_data["failure"] = serde_json::to_value(failure)
                .unwrap_or_else(|_| serde_json::json!({ "serialization_error": true }));
        }
        let report_data = match child_routing.as_ref() {
            Some(routing) => with_child_routing_metadata(report_data, routing),
            None => {
                with_model_routing_metadata(report_data, &self.stack.last().unwrap().agent.model)
            }
        };
        // The subagent report is authored by the CHILD model, so route it through
        // the frame-carrying journaling path with the child's trust + pre-policy
        // session table (H2; mirrors the interactive success pop). A frame-less
        // `record_event` skips the trusted journaling branch entirely, so a
        // session-table literal in a trusted child's report would persist raw
        // with no history row. When the child model is untrusted the frame path
        // journals nothing (its report is already post-redaction). `self.redact`
        // is the session's pre-policy table (what the driver hands
        // `Model::for_provider` as the session table). When child routing is
        // unknown, fall back to the plain path (today's semantics).
        let record_result = match child_routing.as_ref() {
            Some(routing) => {
                self.session
                    .record_event_with_model_frame(
                        crate::db::session_log::SessionEventKind::SubagentReport,
                        Some(&child_agent),
                        Some(&task_call_id),
                        crate::session::SessionEventModelFrame {
                            provider_id: &routing.provider,
                            model_id: &routing.model,
                            config: &self.config,
                            session_table: self.redact.as_ref(),
                        },
                        &report_data,
                    )
                    .await
            }
            None => {
                self.session
                    .record_event(
                        crate::db::session_log::SessionEventKind::SubagentReport,
                        Some(&child_agent),
                        Some(&task_call_id),
                        &report_data,
                    )
                    .await
            }
        };
        if let Err(e) = record_result {
            tracing::warn!(error = %e, "record subagent_report event failed");
        }
        let fallback_routing =
            || ChildRoutingMetadata::from_parent_model(&self.stack.last().unwrap().agent.model);
        let routing = child_routing
            .as_ref()
            .cloned()
            .unwrap_or_else(fallback_routing);
        let _ = tx
            .send(TurnEvent::SubagentReport {
                agent: child_agent.clone(),
                task_call_id: task_call_id.clone(),
                label: "default".to_string(),
                report: report.clone(),
                failed,
                model_trusted: routing.model_trusted,
                routing: routing.routing,
            })
            .await;

        let result = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
            task_call_id.clone(),
            task_provider_item_id,
            task_function_call_id,
            "task",
            report.clone(),
        );
        self.noninteractive_delegations
            .set_snapshot(&task_call_id, "default", snapshot);
        self.noninteractive_delegations.complete(
            &task_call_id,
            "default",
            report.clone(),
            failed,
            Some(result.clone()),
        );
        if let Err(e) = self
            .session
            .db
            .complete_task_delegation_child(&task_call_id, "default", &report, failed, None)
            .await
        {
            tracing::warn!(error = %e, task_call_id, "complete single delegation child failed");
        }
        let _ = self
            .noninteractive_delegations
            .mark_delivered(&task_call_id, "default");
        if apply_shrink && let Some(parent) = self.stack.last_mut() {
            crate::engine::delegation_prompt_prune::prune_completed_delegation_prompts_with_upcoming(
                &mut parent.history,
                Some(&result),
            );
        }
        Ok(result)
    }

    pub(in crate::engine::driver) async fn maybe_scan_task_report(
        &self,
        child_agent: &str,
        report: String,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<String> {
        let guard = crate::config::extended::resolve_injection_guard(&self.cwd);
        let scan = crate::agents::resolve(&self.cwd, child_agent)
            .ok()
            .flatten()
            .map(|def| {
                def.scan_tool_results
                    .unwrap_or_else(|| crate::agents::default_scan_tool_results(&def.name))
            })
            .unwrap_or_else(|| !matches!(child_agent, "explore" | "scout" | "docs-answerer"));
        if !crate::engine::agent::should_scan_tool_result(
            "task",
            scan,
            self.session.approval_mode(),
            guard.threshold,
        ) {
            return Ok(report);
        }
        let ctx = crate::engine::agent::ResultRecheckCtx {
            agent_id: child_agent.to_string(),
            session: self.session.clone(),
            cwd: self.cwd.clone(),
            config: self.config.clone(),
            redact: self.redact.clone(),
            interrupts: self.interrupts.clone(),
        };
        crate::engine::agent::result_recheck(&report, &ctx, tx).await
    }

    pub(in crate::engine::driver) fn take_pending_noninteractive_completion(
        &mut self,
        task_call_id: &str,
    ) -> Option<BackgroundNoninteractiveCompletion> {
        let pos = self
            .pending_noninteractive_completions
            .iter()
            .position(|completion| completion.task_call_id() == task_call_id)?;
        self.pending_noninteractive_completions.remove(pos)
    }

    pub(in crate::engine::driver) async fn recv_noninteractive_completion_for(
        &mut self,
        task_call_id: &str,
    ) -> Option<BackgroundNoninteractiveCompletion> {
        if let Some(completion) = self.take_pending_noninteractive_completion(task_call_id) {
            return Some(completion);
        }
        loop {
            let completion = self.noninteractive_complete_rx.recv().await?;
            match completion.task_call_id() {
                id if id != task_call_id => {
                    self.pending_noninteractive_completions
                        .push_back(completion);
                }
                _ => return Some(completion),
            }
        }
    }

    pub(in crate::engine::driver) async fn run_next_pending_noninteractive_completion(
        &mut self,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<bool> {
        let Some(completion) = self.pending_noninteractive_completions.pop_front() else {
            return Ok(false);
        };
        self.deliver_background_noninteractive_completion(Some(completion), input_rx, tx)
            .await
    }

    pub(in crate::engine::driver) async fn deliver_background_noninteractive_completion(
        &mut self,
        completion: Option<BackgroundNoninteractiveCompletion>,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<bool> {
        let delivery = self
            .finalize_background_noninteractive_completion(completion, tx)
            .await?;
        self.reap_finished_noninteractive_jobs();
        match delivery {
            NoninteractiveCompletionDelivery::None => Ok(false),
            NoninteractiveCompletionDelivery::Inline(message) => {
                self.run_parent_tool_result(message, tx).await?;
                Ok(true)
            }
            NoninteractiveCompletionDelivery::AsyncUser(text) => {
                if text.trim().is_empty() {
                    return Ok(false);
                }
                self.run_user_input(UserSubmission::text(text), input_rx, tx)
                    .await?;
                Ok(true)
            }
        }
    }

    /// Claim the one-time delivery of a background noninteractive job so both the
    /// report delivery and the paired `subagentStop` fire exactly once. Returns:
    /// - `First`: this call transitioned the job from undelivered → delivered;
    ///   deliver the report AND fire the stops.
    /// - `AlreadyDelivered`: a prior call already delivered; return `None`.
    /// - `NoJob`: the job is absent (reaped after an earlier delivery, or removed
    ///   by a whole-job cancel that already fired the stops). The report is still
    ///   delivered for backward compatibility, but the stops are NOT re-fired.
    fn claim_noninteractive_delivery(&mut self, task_call_id: &str) -> NoninteractiveDeliveryClaim {
        match self.noninteractive_jobs.get_mut(task_call_id) {
            Some(job) if job.delivered => NoninteractiveDeliveryClaim::AlreadyDelivered,
            Some(job) => {
                job.delivered = true;
                NoninteractiveDeliveryClaim::First
            }
            None => NoninteractiveDeliveryClaim::NoJob,
        }
    }

    /// Fire one terminal `subagentStop` G::Stop dispatch for every NONINTERACTIVE child
    /// registered under `task_call_id`, at the delegation-complete / delivery
    /// boundary. Pairs 1:1 with the `subagentStart` fired at `register_running`:
    /// every started noninteractive child (a single delegation, or each entry of
    /// a batch delegation) emits exactly one stop. Called only from the
    /// delivered-transition arms of
    /// [`Self::finalize_background_noninteractive_completion`] (guarded by
    /// `job.delivered`), so it runs once per delivered job and cannot double-fire
    /// across the inline-finish and background-delivery paths.
    ///
    /// `endReason` reflects each child's terminal registry status set by
    /// `finalize_single_*` / `finalize_batch_*`; `fallback` covers a child whose
    /// entry was never `complete()`d (a tokio-level `Err` / whole-batch abort of
    /// a started child). Child-only; matcher / `subagentType` is the child agent
    /// type and `subagentId` is the shared delegating `task` call id. Envelope
    /// carries only camelCase `subagentId` / `subagentType` / `endReason` — no
    /// child prompt text, report body, tool IO, or history.
    async fn fire_noninteractive_subagent_stops(&self, task_call_id: &str, fallback: &'static str) {
        // Collect first so no borrow of the registry is held across the await in
        // hook dispatch. Stable order (by label) for deterministic firing.
        let mut children: Vec<(String, String, &'static str)> = self
            .noninteractive_delegations
            .entries
            .iter()
            .filter(|(key, _)| key.task_call_id == task_call_id)
            // Normal completion already ran the controlling child-owned stop
            // gate before producing this report. Only abnormal terminal paths
            // need the observe-only pairing here.
            .filter(|(_, entry)| entry.status != NoninteractiveDelegationStatus::Completed)
            .filter(|(_, entry)| !entry.lifecycle.emitted())
            .map(|(key, entry)| {
                (
                    key.label.clone(),
                    entry.child_agent.clone(),
                    noninteractive_end_reason(entry.status, fallback),
                )
            })
            .collect();
        children.sort_by(|a, b| a.0.cmp(&b.0));
        for (_label, child_agent, end_reason) in children {
            let snapshot = self.config.snapshot();
            let runner = self.hook_runner();
            let mut discarded = crate::engine::agent::hooks::StopGateState::default();
            let _ = crate::engine::agent::hooks::run_stop_hooks(
                &runner,
                &crate::engine::agent::hooks::DefaultProcessEnv,
                snapshot.hooks(),
                crate::config::extended::hooks::HookEvent::SubagentStop,
                &child_agent,
                self.session.id,
                &self.cwd,
                &self.session.db,
                Some(&child_agent),
                Some(task_call_id),
                Some(end_reason),
                &mut discarded,
            )
            .await;
        }
    }

    pub(in crate::engine::driver) async fn finalize_background_noninteractive_completion(
        &mut self,
        completion: Option<BackgroundNoninteractiveCompletion>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<NoninteractiveCompletionDelivery> {
        let Some(completion) = completion else {
            return Ok(NoninteractiveCompletionDelivery::None);
        };
        match completion {
            BackgroundNoninteractiveCompletion::Single {
                task_call_id,
                task_provider_item_id,
                task_function_call_id,
                result,
            } => match *result {
                Ok(completion) => {
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    let first_delivery = self.claim_noninteractive_delivery(&task_call_id);
                    if first_delivery.already_delivered() {
                        return Ok(NoninteractiveCompletionDelivery::None);
                    }
                    let finalized = self
                        .finalize_single_noninteractive_task(completion, tx, !was_backgrounded)
                        .await;
                    // `subagentStop` observe hook for the delivered NONINTERACTIVE
                    // child. Fired ONLY on the tracked first delivery (a job that
                    // was cancelled+aborted fires its stop on the cancel path
                    // instead, and a re-delivered completion never reaches here),
                    // so it cannot double-fire across inline finish / background
                    // delivery / cancel. Fired even if `finalize_single_*` errored,
                    // so a scan/expand failure can't drop the stop; on that error
                    // the entry is un-`complete()`d and falls back to `failed`.
                    // Pairs the `subagentStart` fired at register-running.
                    if first_delivery.fire_stops() {
                        self.fire_noninteractive_subagent_stops(&task_call_id, "failed")
                            .await;
                    }
                    let result = finalized?;
                    if was_backgrounded {
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .await
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        if let Err(e) = self
                            .session
                            .db
                            .mark_task_delegation_child_delivered(&task_call_id, "default")
                            .await
                        {
                            tracing::warn!(error = %e, task_call_id, "mark inline single delegation delivered failed");
                        }
                        Ok(NoninteractiveCompletionDelivery::Inline(result))
                    }
                }
                Err(e) => {
                    let body = format!("Error: {e:#}");
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    let first_delivery = self.claim_noninteractive_delivery(&task_call_id);
                    if first_delivery.already_delivered() {
                        return Ok(NoninteractiveCompletionDelivery::None);
                    }
                    // The started child failed at the delegation runtime level (the
                    // spawned task itself returned `Err`), so its registry entry was
                    // never `complete()`d; fall back to `failed`. Exactly one stop
                    // per started child on the tracked first delivery.
                    if first_delivery.fire_stops() {
                        self.fire_noninteractive_subagent_stops(&task_call_id, "failed")
                            .await;
                    }
                    if was_backgrounded {
                        self.record_background_noninteractive_error(&task_call_id, &body)
                            .await;
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .await
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        Ok(NoninteractiveCompletionDelivery::Inline(
                            crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                "task",
                                body,
                            ),
                        ))
                    }
                }
            },
            BackgroundNoninteractiveCompletion::Batch {
                task_call_id,
                task_provider_item_id,
                task_function_call_id,
                result,
            } => match *result {
                Ok(completion) => {
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    let first_delivery = self.claim_noninteractive_delivery(&task_call_id);
                    if first_delivery.already_delivered() {
                        return Ok(NoninteractiveCompletionDelivery::None);
                    }
                    let result = self
                        .finalize_batch_noninteractive_task(completion, tx)
                        .await;
                    // One `subagentStop` per started NONINTERACTIVE batch child, on
                    // the tracked first delivery. `finalize_batch_*` just set each
                    // child's terminal registry status, so `endReason` is exact per
                    // child (a whole-batch abort leaves them un-`complete()`d and
                    // falls back to `failed`). Pairs the per-entry `subagentStart`
                    // fired at register-running.
                    if first_delivery.fire_stops() {
                        self.fire_noninteractive_subagent_stops(&task_call_id, "failed")
                            .await;
                    }
                    if was_backgrounded {
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .await
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        match self
                            .session
                            .db
                            .undelivered_task_delegation_children(&task_call_id)
                            .await
                        {
                            Ok(rows) => {
                                for row in rows {
                                    if let Err(e) = self
                                        .session
                                        .db
                                        .mark_task_delegation_child_delivered(
                                            &task_call_id,
                                            &row.label,
                                        )
                                        .await
                                    {
                                        tracing::warn!(error = %e, task_call_id, label = %row.label, "mark inline batch delegation delivered failed");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, task_call_id, "load inline batch delegation rows failed");
                            }
                        }
                        Ok(NoninteractiveCompletionDelivery::Inline(result))
                    }
                }
                Err(e) => {
                    let body = format!("Error: {e:#}");
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    let first_delivery = self.claim_noninteractive_delivery(&task_call_id);
                    if first_delivery.already_delivered() {
                        return Ok(NoninteractiveCompletionDelivery::None);
                    }
                    // Whole-batch runtime failure (the spawned task returned `Err`):
                    // no child was `complete()`d, so every registered batch child
                    // falls back to `failed`. One stop per started child on the
                    // tracked first delivery, pairing the per-entry start.
                    if first_delivery.fire_stops() {
                        self.fire_noninteractive_subagent_stops(&task_call_id, "failed")
                            .await;
                    }
                    if was_backgrounded {
                        self.record_background_noninteractive_error(&task_call_id, &body)
                            .await;
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .await
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        Ok(NoninteractiveCompletionDelivery::Inline(
                            crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id,
                                task_function_call_id,
                                "task",
                                body,
                            ),
                        ))
                    }
                }
            },
        }
    }

    pub(in crate::engine::driver) fn reap_finished_noninteractive_jobs(&mut self) {
        self.noninteractive_jobs.retain(|task_call_id, job| {
            let reap = job.delivered && job.handle.is_finished();
            if reap {
                tracing::debug!(task_call_id, "reaped delivered noninteractive job handle");
            }
            !reap
        });
    }

    /// Cooperatively settle every live background child before the driver is
    /// torn down.  Dropping/aborting the join handles would race child-owned
    /// stop gates and strand completion reconciliation in the foreground
    /// registry.  Cancellation is broadcast first, then every task is joined,
    /// and finally every terminal message is reconciled while this driver still
    /// owns the registry and hook dispatcher.
    pub(crate) async fn settle_noninteractive_jobs_for_teardown(
        &mut self,
        tx: &mpsc::Sender<TurnEvent>,
    ) {
        let jobs = std::mem::take(&mut self.noninteractive_jobs);
        let task_ids: Vec<String> = jobs.keys().cloned().collect();
        for job in jobs.values() {
            job.cancel.cancel();
        }
        // Drain completions concurrently with joins. A child can otherwise be
        // blocked publishing into the bounded completion channel while the
        // teardown owner waits for that same child to join.
        let mut joins = tokio::task::JoinSet::new();
        for (task_call_id, job) in jobs {
            joins.spawn(async move { (task_call_id, job.handle.await) });
        }
        let mut completions: Vec<BackgroundNoninteractiveCompletion> =
            self.pending_noninteractive_completions.drain(..).collect();
        let mut completion_channel_open = true;
        while !joins.is_empty() {
            tokio::select! {
                joined = joins.join_next() => {
                    if let Some(Ok((task_call_id, Err(error)))) = joined {
                        tracing::warn!(%error, %task_call_id, "background child failed while joining teardown");
                    }
                }
                completion = self.noninteractive_complete_rx.recv(), if completion_channel_open => {
                    match completion {
                        Some(completion) => completions.push(completion),
                        None => completion_channel_open = false,
                    }
                }
            }
        }
        while let Ok(completion) = self.noninteractive_complete_rx.try_recv() {
            completions.push(completion);
        }
        // The job map was deliberately taken so Drop cannot abort a joined
        // child. Pair every child whose controlling gate did not publish its
        // shared latch before consuming completion payloads; finalization sees
        // NoJob and therefore cannot emit a duplicate.
        for task_call_id in &task_ids {
            self.fire_noninteractive_subagent_stops(task_call_id, "aborted")
                .await;
        }
        for completion in completions {
            if let Err(error) = self
                .finalize_background_noninteractive_completion(Some(completion), tx)
                .await
            {
                tracing::warn!(%error, "background child completion reconciliation failed during teardown");
            }
        }
    }

    pub(in crate::engine::driver) async fn release_noninteractive_child_locks(
        &self,
        rows: &[crate::db::task_delegations::DelegationChildDetail],
    ) {
        let mut released = std::collections::HashSet::new();
        for row in rows {
            if !released.insert(row.child_agent.as_str()) {
                continue;
            }
            if let Err(e) = self
                .locks
                .suspend_agent(&row.child_agent, self.session.id)
                .await
            {
                tracing::warn!(
                    error = ?e,
                    agent = %row.child_agent,
                    task_call_id = %row.task_call_id,
                    "release noninteractive child locks after abort failed"
                );
            }
        }
    }

    pub(in crate::engine::driver) async fn record_background_noninteractive_error(
        &mut self,
        task_call_id: &str,
        body: &str,
    ) {
        let rows = match self
            .session
            .db
            .list_task_delegation_children(self.session.id)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "load task delegation rows for background error failed");
                return;
            }
        };
        for row in rows
            .into_iter()
            .filter(|row| row.task_call_id == task_call_id && delegation_status_live(row.status))
        {
            if let Err(e) = self
                .session
                .db
                .complete_task_delegation_child(task_call_id, &row.label, body, true, None)
                .await
            {
                tracing::warn!(error = %e, task_call_id, label = %row.label, "complete errored background delegation child failed");
            }
            self.noninteractive_delegations.complete(
                task_call_id,
                &row.label,
                body.to_string(),
                true,
                None,
            );
        }
    }

    pub(in crate::engine::driver) async fn background_delegation_ack(
        &mut self,
        task_call_id: &str,
        task_provider_item_id: Option<String>,
        task_function_call_id: Option<String>,
    ) -> Message {
        let completed = self
            .noninteractive_delegations
            .completed_undelivered(task_call_id);
        let running = self.noninteractive_delegations.running_labels(task_call_id);
        for (label, _) in &completed {
            let _ = self
                .noninteractive_delegations
                .mark_delivered(task_call_id, label);
            if let Err(e) = self
                .session
                .db
                .mark_task_delegation_child_delivered(task_call_id, label)
                .await
            {
                tracing::warn!(error = %e, task_call_id, label, "mark delegation ack child delivered failed");
            }
        }
        let body = format_delegation_background_ack(task_call_id, &completed, &running);
        crate::engine::message::synthetic_tool_result_message_with_provider_identity(
            task_call_id.to_string(),
            task_provider_item_id,
            task_function_call_id,
            "task",
            body,
        )
    }

    pub(in crate::engine::driver) async fn async_delegation_result(
        &mut self,
        task_call_id: &str,
    ) -> Option<String> {
        let completed = match self
            .session
            .db
            .undelivered_task_delegation_children(task_call_id)
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|row| AsyncDelegationChildResult {
                    label: row.label,
                    status: row.status.as_str().to_string(),
                    report: row.report,
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "load undelivered delegation children failed");
                self.noninteractive_delegations
                    .completed_undelivered(task_call_id)
                    .into_iter()
                    .map(|(label, report)| AsyncDelegationChildResult {
                        label,
                        status: "completed".to_string(),
                        report: Some(report),
                    })
                    .collect::<Vec<_>>()
            }
        };
        if completed.is_empty() {
            return None;
        }
        for child in &completed {
            let _ = self
                .noninteractive_delegations
                .mark_delivered(task_call_id, &child.label);
            if let Err(e) = self
                .session
                .db
                .mark_task_delegation_child_delivered(task_call_id, &child.label)
                .await
            {
                let label = child.label.as_str();
                tracing::warn!(error = %e, task_call_id, label, "mark async delegation child delivered failed");
            }
        }
        let running = self.noninteractive_delegations.running_labels(task_call_id);
        Some(format_async_delegation_result(
            task_call_id,
            &completed,
            &running,
        ))
    }

    pub(in crate::engine::driver) async fn enqueue_delegation_steer(
        &mut self,
        target_task_call_id: Option<String>,
        label: Option<String>,
        body: String,
        origin_principal: String,
        scrubbed: bool,
    ) -> std::result::Result<crate::daemon::proto::DelegationSteerResult, String> {
        let rows = self
            .session
            .db
            .list_task_delegation_children(self.session.id)
            .await
            .map_err(|e| format!("could not load task delegations: {e:#}"))?;
        let orphaned = orphaned_task_control_keys(&rows, &self.noninteractive_delegations);
        let selected =
            match resolve_task_control_targets(&rows, target_task_call_id.clone(), label, false) {
                Ok(selected) => selected,
                Err(reason) => {
                    return Ok(crate::daemon::proto::DelegationSteerResult::not_steerable(
                        target_task_call_id.unwrap_or_default(),
                        None,
                        reason,
                    ));
                }
            };
        if selected.len() != 1 {
            return Ok(crate::daemon::proto::DelegationSteerResult::not_steerable(
                target_task_call_id.unwrap_or_default(),
                None,
                "steer requires exactly one delegation child".to_string(),
            ));
        }
        let row = &selected[0];
        if !task_control_actionable_live(row, &orphaned, &self.noninteractive_delegations) {
            let reason = if orphaned.contains(&task_control_key(row)) {
                "lost (daemon restarted; no live worker)".to_string()
            } else {
                delegation_status_name(row.status).to_string()
            };
            return Ok(crate::daemon::proto::DelegationSteerResult::not_steerable(
                row.task_call_id.clone(),
                Some(row.label.clone()),
                reason,
            ));
        }
        if body.trim().is_empty() {
            return Ok(crate::daemon::proto::DelegationSteerResult::not_steerable(
                row.task_call_id.clone(),
                Some(row.label.clone()),
                "message is required for steer".to_string(),
            ));
        }
        self.session
            .db
            .enqueue_task_delegation_steer(&row.task_call_id, &row.label, &body, &origin_principal)
            .await
            .map_err(|e| format!("could not persist steer: {e:#}"))?;
        self.noninteractive_delegations
            .push_steer(&row.task_call_id, &row.label, body);
        Ok(crate::daemon::proto::DelegationSteerResult::queued(
            row.task_call_id.clone(),
            row.label.clone(),
            row.pending_steers + 1,
            origin_principal,
            scrubbed,
        ))
    }

    pub(in crate::engine::driver) async fn dispatch_task_control(
        &mut self,
        action: TaskControlAction,
        target_task_call_id: Option<String>,
        label: Option<String>,
        message: Option<String>,
    ) -> String {
        if matches!(action, TaskControlAction::Models) {
            return match self.live_providers_config() {
                Ok(providers) => crate::engine::model_roles::render_model_discovery(
                    self.active_agent(),
                    &providers,
                ),
                Err(e) => format!("Error: could not load provider model policy: {e:#}"),
            };
        }
        let rows = match self
            .session
            .db
            .list_task_delegation_children(self.session.id)
            .await
        {
            Ok(rows) => rows,
            Err(e) => return format!("Error: could not load task delegations: {e:#}"),
        };
        let orphaned = orphaned_task_control_keys(&rows, &self.noninteractive_delegations);
        match action {
            TaskControlAction::Models => unreachable!("handled before task delegation DB lookup"),
            TaskControlAction::List => format_task_control_list(&rows, &orphaned),
            TaskControlAction::Status => {
                let selected = match resolve_task_control_targets(
                    &rows,
                    target_task_call_id.clone(),
                    label,
                    false,
                ) {
                    Ok(selected) => selected,
                    Err(e) => return e,
                };
                format_task_control_status(&selected, &orphaned)
            }
            TaskControlAction::Cancel => {
                let selected = match resolve_task_control_targets(
                    &rows,
                    target_task_call_id.clone(),
                    label.clone(),
                    true,
                ) {
                    Ok(selected) => selected,
                    Err(e) => return e,
                };
                let cancel_whole_job = target_task_call_id.is_some() && label.is_none();
                if cancel_whole_job
                    && let Some(task_call_id) = selected.first().map(|row| row.task_call_id.clone())
                    && let Some(job) = self.noninteractive_jobs.get(&task_call_id)
                {
                    // Cancellation is cooperative. The child owns any in-flight
                    // stop gate and publishes its terminal completion only after
                    // hook containment cleanup has settled; delivery remains the
                    // sole place that pairs abnormal lifecycle notifications.
                    job.cancel.cancel();
                }
                let mut changed = Vec::new();
                let mut unchanged = Vec::new();
                let mut orphaned_lost = Vec::new();
                for row in selected {
                    let key = task_control_key(&row);
                    if orphaned.contains(&key) {
                        match self
                            .session
                            .db
                            .mark_task_delegation_child_lost(&row.task_call_id, &row.label)
                            .await
                        {
                            Ok(true) => {
                                let _ = self
                                    .session
                                    .db
                                    .finish_task_assignment(
                                        self.session.id,
                                        &row.task_call_id,
                                        &row.label,
                                        "lost",
                                        None,
                                    )
                                    .await;
                                orphaned_lost.push(format!("{}:{}", row.task_call_id, row.label))
                            }
                            Ok(false) => unchanged.push(format!(
                                "{}:{} ({})",
                                row.task_call_id,
                                row.label,
                                task_control_row_status_name(&row, &orphaned)
                            )),
                            Err(e) => {
                                return format!(
                                    "Error: could not mark orphaned `{}`/`{}` lost: {e:#}",
                                    row.task_call_id, row.label
                                );
                            }
                        }
                        continue;
                    }
                    let live_changed = self
                        .noninteractive_delegations
                        .cancel(&row.task_call_id, &row.label);
                    let db_changed = match self
                        .session
                        .db
                        .cancel_task_delegation_child(&row.task_call_id, &row.label)
                        .await
                    {
                        Ok(changed) => changed,
                        Err(e) => {
                            return format!(
                                "Error: could not cancel `{}`/`{}`: {e:#}",
                                row.task_call_id, row.label
                            );
                        }
                    };
                    let _ = self
                        .session
                        .db
                        .finish_task_assignment(
                            self.session.id,
                            &row.task_call_id,
                            &row.label,
                            "cancelled",
                            None,
                        )
                        .await;
                    if live_changed || db_changed {
                        changed.push(format!("{}:{}", row.task_call_id, row.label));
                    } else {
                        unchanged.push(format!(
                            "{}:{} ({})",
                            row.task_call_id,
                            row.label,
                            task_control_row_status_name(&row, &orphaned)
                        ));
                    }
                }
                let state = if changed.is_empty() && orphaned_lost.is_empty() {
                    "no_change"
                } else if !orphaned_lost.is_empty() && changed.is_empty() {
                    "lost"
                } else {
                    "cancelled"
                };
                task_envelope(serde_json::json!({
                    "state": state,
                    "task_call_id": target_task_call_id,
                    "blocking": false,
                    "tool_call_closed": true,
                    "result_pending": false,
                    "report_available": false,
                    "report_delivered": false,
                    "cancelled": changed,
                    "orphaned_lost": orphaned_lost,
                    "unchanged": unchanged,
                    "children": [],
                }))
            }
            TaskControlAction::Query => {
                let selected = match resolve_task_control_targets(
                    &rows,
                    target_task_call_id.clone(),
                    label,
                    false,
                ) {
                    Ok(selected) => selected,
                    Err(e) => return e,
                };
                if selected.len() != 1 {
                    return task_envelope(serde_json::json!({
                        "state": "refused",
                        "task_call_id": target_task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": false,
                        "report_delivered": false,
                        "actionable": false,
                        "reason": "query requires exactly one delegation child",
                        "children": [],
                    }));
                }
                let row = &selected[0];
                if !task_control_actionable_live(row, &orphaned, &self.noninteractive_delegations) {
                    let reason = if orphaned.contains(&task_control_key(row)) {
                        "lost (daemon restarted; no live worker)".to_string()
                    } else {
                        delegation_status_name(row.status).to_string()
                    };
                    let report_source = if row.report.is_some() { "db" } else { "none" };
                    let mut value = serde_json::json!({
                        "state": "refused",
                        "task_call_id": row.task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": row.report.is_some(),
                        "report_delivered": row.result_delivered,
                        "actionable": false,
                        "reason": reason,
                        "report_source": report_source,
                        "children": [task_child_detail_json(row, &orphaned)],
                    });
                    if let Some(report) = &row.report {
                        value["report"] = serde_json::json!(crate::text::cap_chars(report, 1200).0);
                    }
                    return task_envelope(value);
                }
                let db_report = row.report.clone();
                let live_report = self
                    .noninteractive_delegations
                    .snapshot_report(&row.task_call_id, &row.label);
                let (report_source, report) = if let Some(report) = db_report {
                    ("db", report)
                } else if let Some(report) = live_report {
                    ("live_snapshot", report)
                } else {
                    (
                        "none",
                        "No report yet; child is still running/backgrounded.".to_string(),
                    )
                };
                task_envelope(serde_json::json!({
                    "state": "query",
                    "task_call_id": row.task_call_id,
                    "blocking": false,
                    "tool_call_closed": row.status != crate::db::task_delegations::DelegationStatus::Running,
                    "result_pending": false,
                    "report_available": report_source != "none",
                    "report_delivered": row.result_delivered,
                    "actionable": true,
                    "read_only": true,
                    "child_state_unchanged": true,
                    "report_source": report_source,
                    "children": [task_child_detail_json(row, &orphaned)],
                    "report": crate::text::cap_chars(&report, 1200).0,
                }))
            }
            TaskControlAction::Steer => {
                let selected = match resolve_task_control_targets(
                    &rows,
                    target_task_call_id.clone(),
                    label,
                    false,
                ) {
                    Ok(selected) => selected,
                    Err(e) => return e,
                };
                if selected.len() != 1 {
                    return task_envelope(serde_json::json!({
                        "state": "refused",
                        "task_call_id": target_task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": false,
                        "report_delivered": false,
                        "actionable": false,
                        "reason": "steer requires exactly one delegation child",
                        "children": [],
                    }));
                }
                let row = &selected[0];
                if !task_control_actionable_live(row, &orphaned, &self.noninteractive_delegations) {
                    let reason = if orphaned.contains(&task_control_key(row)) {
                        "lost (daemon restarted; no live worker)".to_string()
                    } else {
                        delegation_status_name(row.status).to_string()
                    };
                    return task_envelope(serde_json::json!({
                        "state": "refused",
                        "task_call_id": row.task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": row.report.is_some(),
                        "report_delivered": row.result_delivered,
                        "actionable": false,
                        "reason": reason,
                        "children": [task_child_detail_json(row, &orphaned)],
                    }));
                }
                let Some(body) = message else {
                    return task_envelope(serde_json::json!({
                        "state": "refused",
                        "task_call_id": row.task_call_id,
                        "blocking": false,
                        "tool_call_closed": true,
                        "result_pending": false,
                        "report_available": row.report.is_some(),
                        "report_delivered": row.result_delivered,
                        "actionable": false,
                        "reason": "message is required for steer",
                        "children": [task_child_detail_json(row, &orphaned)],
                    }));
                };
                match self
                    .enqueue_delegation_steer(
                        Some(row.task_call_id.clone()),
                        Some(row.label.clone()),
                        body,
                        format!("agent:{}", row.task_call_id),
                        false,
                    )
                    .await
                {
                    Ok(result) => task_envelope(result.to_task_envelope_value()),
                    Err(message) => format!("Error: {message}"),
                }
            }
        }
    }

    pub(in crate::engine::driver) async fn run_batch_noninteractive_task_backgroundable(
        &mut self,
        mut task: BatchNoninteractiveTask,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Message> {
        let task_call_id = task.task_call_id.clone();
        let task_provider_item_id = task.task_provider_item_id.clone();
        let task_function_call_id = task.task_function_call_id.clone();
        // FAIL CLOSED before ANY batch persist / registration: validate EVERY
        // entry's child (or docs-stage) model. An unresolvable entry returns the
        // content-safe routing error having persisted no task, registered no
        // running child, and spawned nothing.
        for (entry, child_cwd) in task.entries.iter().zip(task.child_cwds.iter()) {
            if let Err(err) = self.preflight_batch_entry(entry, child_cwd) {
                return Ok(
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "task",
                        prepend_task_repair_notes(err, &task.repair_notes),
                    ),
                );
            }
        }
        // Reserve the whole batch before it is persisted or registered. The
        // non-waiting registry either admits every direct child together or
        // refuses the call with no partial batch lifecycle side effect.
        let vnext_admissions = match self.admit_current_vnext_children(task.entries.len()) {
            Ok(permits) => permits,
            Err(err) => {
                return Ok(
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "task",
                        prepend_task_repair_notes(err, &task.repair_notes),
                    ),
                );
            }
        };
        let child_todo_json = task
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.label.clone(),
                    serde_json::to_string(&entry.todo_ids).ok(),
                )
            })
            .collect::<std::collections::HashMap<_, _>>();
        let child_cwd_displays = task
            .child_cwds
            .iter()
            .map(ChildCwd::resolved_display)
            .collect::<Vec<_>>();
        let child_model_displays = task
            .entries
            .iter()
            .map(|entry| model_selector_display(&entry.model))
            .collect::<Vec<_>>();
        let child_inits = task
            .entries
            .iter()
            .zip(task.child_cwds.iter())
            .zip(child_cwd_displays.iter())
            .zip(child_model_displays.iter())
            .map(|(((entry, child_cwd), resolved_cwd), model)| {
                crate::db::task_delegations::DelegationChildInit {
                    label: entry.label.as_str(),
                    child_agent: entry.child_agent.as_str(),
                    model: model.as_deref(),
                    output_dir: entry.write_scope.as_deref(),
                    requested_cwd: child_cwd.requested_json(),
                    resolved_cwd: Some(resolved_cwd.as_str()),
                    todo_ids_json: child_todo_json
                        .get(&entry.label)
                        .and_then(|value| value.as_deref()),
                }
            })
            .collect::<Vec<_>>();
        let task_args_json = serde_json::to_string(&serde_json::json!({
            "entries": task.entries.iter().zip(task.child_cwds.iter()).map(|(entry, child_cwd)| serde_json::json!({
                "label": &entry.label,
                "child_agent": &entry.child_agent,
                "model": model_selector_json(&entry.model),
                "context": entry.context.as_str(),
                "resume_handle": &entry.resume_handle,
                "requested_cwd": child_cwd.requested_json(),
                "resolved_cwd": child_cwd.resolved_display(),
                "write_scope": &entry.write_scope,
                "todo_ids": &entry.todo_ids,
            })).collect::<Vec<_>>(),
            "why": &task.why,
        }))
        .ok();
        let parent_agent = self.stack.last().unwrap().agent.name.clone();
        let payloads = task
            .entries
            .iter()
            .map(
                |entry| crate::db::task_delegation_payloads::NewTaskDelegationPayload {
                    task_call_id: task_call_id.as_str(),
                    function_call_id: task_function_call_id.as_deref(),
                    parent_session_id: self.session.id,
                    parent_agent: parent_agent.as_str(),
                    label: entry.label.as_str(),
                    child_agent: entry.child_agent.as_str(),
                    prompt: entry.prompt.as_str(),
                },
            )
            .collect::<Vec<_>>();
        match self
            .session
            .db
            .upsert_task_delegation_job_and_payloads(
                crate::db::task_delegations::TaskDelegationJobUpsert {
                    session_id: self.session.id,
                    task_call_id: &task_call_id,
                    function_call_id: task_function_call_id.as_deref(),
                    parent_agent: &parent_agent,
                    original_args_json: task_args_json.as_deref(),
                    children: &child_inits,
                },
                payloads,
            )
            .await
        {
            Ok(rows) => {
                for (entry, row) in task.entries.iter_mut().zip(rows.iter()) {
                    if entry.context == crate::engine::agent::TaskContext::Fresh {
                        entry.prompt = delegation_payload_reference_prompt(row);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "persist batch task delegation job and payloads failed");
                return Ok(
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "task",
                        prepend_task_repair_notes(
                            DELEGATION_PAYLOAD_REFUSAL.to_string(),
                            &task.repair_notes,
                        ),
                    ),
                );
            }
        }
        for entry in &task.entries {
            self.noninteractive_delegations.register_running_for_session(
                self.session.id,
                &task_call_id,
                &entry.label,
                entry.child_agent.clone(),
                NoninteractiveDelegationSnapshot::empty(),
            );
            // `subagentStart` observe hook per NONINTERACTIVE batch child, at the
            // same register-running boundary as the single path: the durable job
            // persisted and the pre-spawn payload-upsert refusal already returned
            // above, so this fires once per child that actually starts. Child-only;
            // matcher / `subagentType` is the child agent type, `subagentId` is the
            // shared delegating `task` call id. Each is paired with exactly one
            // `subagentStop` at delegation delivery.
            let child_lifecycle_id =
                crate::db::task_delegations::delegation_child_lifecycle_id_for_session(
                    self.session.id,
                    &task_call_id,
                    &entry.label,
                );
            self.fire_subagent_hook(&entry.child_agent, Some(&child_lifecycle_id))
            .await;
        }
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let completion_task_call_id = task_call_id.clone();
        let completion_task_provider_item_id = task_provider_item_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
        let job_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            let result = runner
                .execute_batch_noninteractive_task_with_admissions(
                    task,
                    vnext_admissions,
                    &tx_for_task,
                    cancel,
                )
                .await;
            let _ = complete_tx
                .send(BackgroundNoninteractiveCompletion::Batch {
                    task_call_id: completion_task_call_id,
                    task_provider_item_id: completion_task_provider_item_id,
                    task_function_call_id: completion_task_function_call_id,
                    result: Box::new(result),
                })
                .await;
        });
        self.noninteractive_jobs.insert(
            task_call_id.clone(),
            BackgroundNoninteractiveJob {
                delivered: false,
                handle,
                cancel: job_cancel,
            },
        );
        tokio::select! {
            biased;
            user = input_rx.recv() => {
                let Some(first) = user else {
                    return Ok(Message::user(""));
                };
                let queue_item_ids = first.queue_item_ids.clone();
                if self
                    .requeue_command_submission_for_boundary(input_rx, first.clone())
                    .await
                {
                    let completion = self.recv_noninteractive_completion_for(&task_call_id).await;
                    let delivery = self
                        .finalize_background_noninteractive_completion(completion, tx)
                        .await?;
                    self.reap_finished_noninteractive_jobs();
                    return Ok(delivery.into_inline_message());
                }
                let labels = self
                    .noninteractive_delegations
                    .entries
                    .keys()
                    .filter(|key| key.task_call_id == task_call_id)
                    .map(|key| key.label.clone())
                    .collect::<Vec<_>>();
                for label in labels {
                    self.noninteractive_delegations
                        .background_on_user_input(&task_call_id, &label);
                    if let Err(e) = self
                        .session
                        .db
                        .background_task_delegation_child(&task_call_id, &label)
                        .await
                    {
                        tracing::warn!(error = %e, task_call_id, label, "background batch task delegation failed");
                    }
                }
                let ack = self
                    .background_delegation_ack(
                        &task_call_id,
                        task_provider_item_id.clone(),
                        task_function_call_id.clone(),
                    )
                    .await;
                if let Some(parent) = self.stack.last_mut() {
                    parent.history.push(ack);
                }
                let Some(prepared) = self
                    .prepare_queued_user_submission(first, input_rx, tx)
                    .await
                else {
                    input_rx.finish(&queue_item_ids).await;
                    return Ok(Message::user(""));
                };
                if self.record_queued_user_fold(&prepared, tx).await.is_err() {
                    input_rx
                        .requeue_front_after(
                            prepared,
                            self.active_queue_target(),
                            DURABLE_SUBMISSION_RETRY_BACKOFF,
                        )
                        .await;
                    return Ok(Message::user(""));
                }
                input_rx.finish(&queue_item_ids).await;
                Ok(crate::engine::message::build_user_message(UserSubmission {
                    origin: crate::engine::message::SubmissionOrigin::ExternalRoot,
                    expected_model_state_generation: None,
                    expected_model: None,
                    kind: UserSubmissionKind::User,
                    text: self.with_time_prelude(prepared.text),
                    display_text: None,
                    tag_expansions: Vec::new(),
                    images: prepared.images,
                    forced_skill: None,
                    origin_principal: None,
                    job_id: None,
                    preflight_cleaned: None,
                    queue_item_ids: Vec::new(),
                    client_submissions: Vec::new(),
                    queue_target: None,
                    pending_terminal_disposition: None,
                    run_invocation_id: None,
                }))
            }
            completion = self.recv_noninteractive_completion_for(&task_call_id) => {
                let delivery = self
                    .finalize_background_noninteractive_completion(completion, tx)
                    .await?;
                self.reap_finished_noninteractive_jobs();
                Ok(delivery.into_inline_message())
            }
        }
    }

    #[cfg(test)]
    pub(in crate::engine::driver) async fn execute_batch_noninteractive_task(
        &mut self,
        task: BatchNoninteractiveTask,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<BatchNoninteractiveCompletion> {
        self.execute_batch_noninteractive_task_with_admissions(task, Vec::new(), tx, cancel)
            .await
    }

    async fn execute_batch_noninteractive_task_with_admissions(
        &mut self,
        task: BatchNoninteractiveTask,
        mut vnext_admissions: Vec<tokio::sync::OwnedSemaphorePermit>,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<BatchNoninteractiveCompletion> {
        let BatchNoninteractiveTask {
            entries,
            child_cwds,
            why,
            repair_notes,
            task_call_id,
            task_provider_item_id,
            task_function_call_id,
        } = task;

        let mut batch_refusal: Option<String> = None;
        let mut child_recursions = Vec::with_capacity(entries.len());
        let mut resolved_write_scopes = Vec::with_capacity(entries.len());
        let mut write_capable_scopes = Vec::new();
        let mut has_write_capable_entry = false;
        // The execution surface is THE contract for concurrent admission. Each
        // child's surface (resolved from its OWN selected model) decides whether
        // it may run CONCURRENTLY: a read-only child only when its surface proves
        // it exposes exclusively registered ordinary read-only operations; a
        // write-capable child keeps its existing parent-scoped concurrent
        // write-admission (below); every other child runs serially. The surface
        // is bound to the attempt by its config generation, re-validated when
        // the child's dispatch actually starts.
        let mut concurrent_admissible = Vec::with_capacity(entries.len());
        // Per-entry: did the child PASS the parent-scoped disjoint-scope
        // write-admission gate (real single-writer capability + Frontier +
        // disjoint scopes)? This — NOT a mere requested `write_scope` — is the
        // write half of the concurrency key. Preserved across generation churn
        // (the gate's inputs are frame-stable), so the recompute under churn keeps
        // a legitimately-admitted disjoint-scope writer concurrent while it
        // re-derives read-only eligibility from the fresh surface.
        let mut parent_write_admitted = Vec::with_capacity(entries.len());
        let mut admission_generations = Vec::with_capacity(entries.len());
        for (entry, child_cwd) in entries.iter().zip(child_cwds.iter()) {
            let child_recursion = match self.resolve_task_recursion(
                &entry.child_agent,
                entry.remaining_depth,
                &entry.model,
            ) {
                Ok(ctx) => ctx,
                Err(err) => {
                    batch_refusal = Some(format!("entry `{}`: {err}", entry.label));
                    break;
                }
            };
            // Pin the config generation BEFORE building the child, so the surface
            // is stamped with the generation the child was actually built under
            // (never a newer one from a refresh landing between build and stamp).
            let pinned_generation = self.config.generation();
            let resolved_write_scope = match resolve_write_scope(
                entry.write_scope.as_deref(),
                &child_cwd.resolved,
                &self.cwd,
            ) {
                Ok(scope) => scope,
                Err(err) => {
                    batch_refusal = Some(format!("batch entry `{}`: {err}", entry.label));
                    break;
                }
            };
            // The `docs` pipeline is NOT a `builtin::load`-able agent — `load`
            // explicitly REJECTS docs stage names — and it is NOT a
            // concurrently-admissible read-only leaf: it runs its own 2-stage
            // pipeline (`docs_pipeline::run`) and MUST run under the EXCLUSIVE
            // guard. Validate its posture via the embedded `docs-resolver` (as the
            // preflight does) WITHOUT calling `load("docs")`, then record it as
            // NON-concurrently-admissible and NON-write-admitted.
            if entry.child_agent == "docs" {
                let docs_args = self.spawn_args_delegated_in_cwd(
                    &child_cwd.resolved,
                    false,
                    entry.granted_tools.clone(),
                    entry.model.clone(),
                    child_recursion.clone(),
                );
                if let Err(e) =
                    crate::engine::builtin::resolve_child_model("docs-resolver", &docs_args)
                {
                    batch_refusal = Some(format!("batch entry `{}`: {e:#}", entry.label));
                    break;
                }
                concurrent_admissible.push(false);
                parent_write_admitted.push(false);
                admission_generations.push(pinned_generation);
                child_recursions.push(child_recursion);
                resolved_write_scopes.push(resolved_write_scope);
                continue;
            }
            let child = match crate::engine::builtin::load(
                &entry.child_agent,
                &self.spawn_args_delegated_in_cwd(
                    &child_cwd.resolved,
                    false,
                    entry.granted_tools.clone(),
                    entry.model.clone(),
                    child_recursion.clone(),
                ),
            ) {
                Ok(child) => child,
                Err(e) => {
                    batch_refusal = Some(format!("could not load `{}`: {e:#}", entry.child_agent));
                    break;
                }
            };
            let write_capable = crate::engine::builtin::is_write_capable(&child);
            if write_capable && entry.write_scope.is_none() {
                batch_refusal = Some(format!(
                    "parallel write-capable entry `{}` (`{}`) requires `write_scope`",
                    entry.label, entry.child_agent
                ));
                break;
            }
            if write_capable {
                has_write_capable_entry = true;
                if let Some(scope) = resolved_write_scope.as_ref() {
                    write_capable_scopes.push((entry.label.clone(), scope.clone()));
                }
            }
            // Bind the surface to this child's dispatch args (scoped) and to the
            // generation PINNED before the child was built; derive its
            // concurrent-admission decision. The write half of the key is the
            // child's REAL single-writer capability (`write_capable`), which — for
            // a batch that survives the Frontier + disjoint-scope checks below —
            // is exactly "passed parent write-admission". A requested `write_scope`
            // WITHOUT real write capability never grants concurrency.
            let surface = crate::engine::builtin::surface_for_built_child(
                &child,
                &self.spawn_args_delegated_in_cwd_scoped(
                    &child_cwd.resolved,
                    false,
                    entry.granted_tools.clone(),
                    entry.model.clone(),
                    child_recursion.clone(),
                    DelegationConfinement {
                        lock_identity: None,
                        write_scope: resolved_write_scope.clone(),
                    },
                ),
                pinned_generation,
            );
            concurrent_admissible.push(
                crate::engine::builtin::batch_child_concurrently_admissible(
                    &surface,
                    write_capable,
                ),
            );
            parent_write_admitted.push(write_capable);
            admission_generations.push(surface.config_generation);
            child_recursions.push(child_recursion);
            resolved_write_scopes.push(resolved_write_scope);
        }
        // Parent-request batch admission: whether the PARENT may request a
        // parallel write-capable batch at all is a parent-scoped policy about
        // the parent request, so it is evaluated under the parent frame's
        // posture (decision: pre-selection batch admission stays parent-mode).
        // This is deliberately NOT a child-execution capability — each child's
        // own posture is resolved later at its build. Named distinctly so the
        // root-mode read stays intentional and reviewable.
        let parent_request_llm_mode = self.stack[0].agent.llm_mode;
        if batch_refusal.is_none()
            && has_write_capable_entry
            && !crate::engine::tool::Capability::ScopedParallelWrite
                .enabled(parent_request_llm_mode)
        {
            batch_refusal = Some(
                "parallel write-capable task batches are Frontier-only; use sequential delegation or run in Frontier mode"
                    .to_string(),
            );
        }
        if batch_refusal.is_none()
            && let Some((left_label, left, right_label, right)) =
                overlapping_write_scope_pair(&write_capable_scopes)
        {
            batch_refusal = Some(format!(
                "write_scope overlap between batch entries `{left_label}` (`{}`) and `{right_label}` (`{}`); write-capable scopes must be disjoint",
                left.display(),
                right.display()
            ));
        }
        if let Some(msg) = batch_refusal {
            return Ok(BatchNoninteractiveCompletion {
                task_call_id,
                task_provider_item_id,
                task_function_call_id,
                children: vec![BatchChildCompletion {
                    idx: 0,
                    label: String::new(),
                    child_agent: String::new(),
                    report: format!("Error: {msg}"),
                    failed: true,
                    partial_progress: DelegationPartialProgress::default(),
                    snapshot: NoninteractiveDelegationSnapshot::empty(),
                }],
                repair_notes,
            });
        }
        // NOTE: `pregrant_write_scope` is DEFERRED into each child's future, AFTER
        // that child's post-build generation guard (non-docs) / pre-dispatch docs
        // guard, so a mid-wait generation move never records a lingering
        // write-scope grant for a child that then fails closed.
        for entry in &entries {
            self.noninteractive_delegations.register_running_for_session(
                self.session.id,
                &task_call_id,
                &entry.label,
                entry.child_agent.clone(),
                NoninteractiveDelegationSnapshot::empty(),
            );
        }

        use futures::StreamExt as _;

        let mut runs = futures::stream::FuturesUnordered::new();
        // The surface is the ONLY contract for concurrent admission, enforced by a
        // shared read-write lock each child acquires INSIDE its own future (so the
        // `FuturesUnordered` execution/stack structure is unchanged and the guard
        // is released by RAII on completion, error, or panic):
        //   - a concurrently-admissible child (`parallel_read_only_eligible` OR a
        //     parent-scoped-write-admitted child) takes a SHARED read guard, so
        //     admissible children run concurrently WITH EACH OTHER;
        //   - a NON-admissible child (read-only-sounding but dynamic/nested, or
        //     unknown, and not write-admitted) takes the EXCLUSIVE write guard,
        //     which blocks every read AND write guard — so it runs ALONE, never
        //     concurrently with ANY other child.
        // (A plain `Semaphore` acquired only by non-admissible children would let
        // an admissible child, which took no permit, still overlap it — the write
        // lock is what excludes the admissible readers.)
        let admission_lock = std::sync::Arc::new(tokio::sync::RwLock::new(()));
        let mut children = Vec::new();
        for (
            idx,
            (
                (
                    ((((mut entry, child_cwd), child_recursion), resolved_write_scope), concurrent),
                    entry_parent_write_admitted,
                ),
                admission_generation,
            ),
        ) in entries
            .into_iter()
            .zip(child_cwds)
            .zip(child_recursions)
            .zip(resolved_write_scopes)
            .zip(concurrent_admissible)
            .zip(parent_write_admitted)
            .zip(admission_generations)
            .enumerate()
        {
            let driver = &*self;
            let entry_why = why.clone();
            let entry_task_call_id = task_call_id.clone();
            let parent = self.stack.last().unwrap().agent.name.clone();
            let (delegation_payload_history, delivered_prompt) =
                if entry.context == crate::engine::agent::TaskContext::Fork {
                    (Vec::new(), entry.prompt.clone())
                } else {
                    match self
                        .delegation_payload_delivery(
                            &task_call_id,
                            &entry.label,
                            &entry.prompt,
                            entry.child_agent != "docs",
                        )
                        .await
                    {
                        Ok(delivery) => delivery,
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                task_call_id,
                                label = %entry.label,
                                "batch task delegation payload delivery failed"
                            );
                            children.push(BatchChildCompletion {
                                idx,
                                label: entry.label,
                                child_agent: entry.child_agent,
                                report: DELEGATION_PAYLOAD_REFUSAL.to_string(),
                                failed: true,
                                partial_progress: DelegationPartialProgress::default(),
                                snapshot: NoninteractiveDelegationSnapshot::empty(),
                            });
                            continue;
                        }
                    }
                };
            entry.prompt = delivered_prompt;
            let routing = self
                .stack
                .last()
                .unwrap()
                .agent
                .model
                .routing_metadata_json(None);
            let _ = tx
                .send(TurnEvent::SubagentSpawned {
                    parent: parent.clone(),
                    child: entry.child_agent.clone(),
                    task_call_id: task_call_id.clone(),
                    label: entry.label.clone(),
                    prompt: entry.prompt.clone(),
                    requested_cwd: child_cwd.requested.clone(),
                    resolved_cwd: Some(child_cwd.resolved_display()),
                    model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                    routing: routing.clone(),
                })
                .await;
            let task_identity = crate::engine::task_identity::TaskProviderIdentity::for_task_call(
                &task_call_id,
                task_provider_item_id.as_deref(),
                task_function_call_id.as_deref(),
            );
            // This event embeds the parent model's task `prompt` (model-authored
            // free text that can carry a session-table literal), so route it
            // through the frame-carrying journaling path with the SPAWNING
            // model's trust + pre-policy session table (mirrors the
            // SubagentReport fix). A frame-less `record_event` skips trusted
            // journaling, so a session-table literal in a trusted parent's prompt
            // would persist raw with no history row; an untrusted spawning model
            // journals nothing (payload already post-redaction). The spawning
            // model is `self.stack.last().unwrap().agent.model`; `self.redact`
            // is the session's pre-policy table.
            if let Err(e) = self
                .session
                .record_event_with_model_frame(
                    crate::db::session_log::SessionEventKind::SubagentSpawned,
                    Some(&self.stack.last().unwrap().agent.name),
                    Some(&task_call_id),
                    crate::session::SessionEventModelFrame {
                        provider_id: self.stack.last().unwrap().agent.model.provider_id(),
                        model_id: self.stack.last().unwrap().agent.model.model_id_ref(),
                        config: &self.config,
                        session_table: self.redact.as_ref(),
                    },
                    &serde_json::json!({
                        "child_agent": entry.child_agent.clone(),
                        "task_call_id": task_call_id,
                        "provider_item_id": task_identity.provider_item_id,
                        "provider_call_id": task_identity.provider_call_id,
                        "provider_call_id_source": task_identity.provider_call_id_source,
                        "provider_identity": task_identity.event_identity_json(&task_call_id),
                        "label": entry.label.clone(),
                        "noninteractive": true,
                        "prompt": entry.prompt.clone(),
                        "why": why.clone(),
                        "model": model_selector_json(&entry.model),
                        "model_trusted": self.stack.last().unwrap().agent.model.is_trusted(),
                        "routing": routing,
                        "context": entry.context.as_str(),
                        "remaining_depth": entry.remaining_depth,
                        "resume_handle": entry.resume_handle.clone(),
                        "requested_cwd": child_cwd.requested_json(),
                        "resolved_cwd": child_cwd.resolved_display(),
                        "grant_tools": entry.granted_tools.clone(),
                        "todo_ids": entry.todo_ids.clone(),
                        "write_scope": entry.write_scope.clone(),
                    }),
                )
                .await
            {
                tracing::warn!(error = %e, "record batch subagent_spawned event failed");
            }

            let child_cancel = cancel.clone();
            let child_admission_lock = admission_lock.clone();
            // Each batch child owns one live-child reservation. It is released
            // as soon as that child exits, rather than waiting for slower batch
            // siblings to finish.
            let vnext_admission = vnext_admissions.pop();
            let child_fut = async move {
                let _vnext_admission = vnext_admission;
                // Surface-gated concurrency (RAII, released on completion / error
                // / panic): an admissible child holds a SHARED read guard (runs
                // with other admissible children); a NON-admissible child holds the
                // EXCLUSIVE write guard, blocking every read and write guard, so it
                // runs ALONE — never concurrently with ANY other child.
                //
                // Pin the config to a held snapshot for THIS child's attempt BEFORE
                // deciding the guard class, so admission-generation == run-generation
                // by construction. `driver.config` is the TURN-pinned handle, but
                // `repin()` freezes the LIVE shared generation; deciding the class
                // off one and dispatching off the other could DISAGREE (a
                // now-write-capable child slipping under a shared read guard). With
                // `pinned` frozen the generation cannot move mid-attempt: the guard
                // class, the child build, its dispatch, and the docs pipeline all
                // read `pinned`. A refresh during the RwLock wait intentionally
                // applies to the NEXT attempt (identical to the driver's
                // turn-boundary repin), so there is no generation-move retry — the
                // class is computed ONCE and the matching guard acquired ONCE. NO
                // live `driver.config` read remains inside the attempt.
                let pinned = driver.config.repin();
                // Recompute admissibility from the PINNED surface ONLY if a refresh
                // landed between batch admission (turn-pinned) and this attempt's
                // pin; otherwise the batch-time decision already matches. Read-only
                // eligibility is re-derived under `pinned`; the parent
                // write-admission decided at preflight (`entry_parent_write_admitted`)
                // is frame-stable (real write capability + Frontier + disjoint
                // scopes) and retained.
                let concurrent = if pinned.generation() != admission_generation {
                    let fresh_args = crate::engine::builtin::SpawnArgs {
                        config: pinned.clone(),
                        ..driver.spawn_args_delegated_in_cwd_scoped(
                            &child_cwd.resolved,
                            false,
                            entry.granted_tools.clone(),
                            entry.model.clone(),
                            child_recursion.clone(),
                            DelegationConfinement {
                                lock_identity: None,
                                write_scope: resolved_write_scope.clone(),
                            },
                        )
                    };
                    match crate::engine::builtin::resolve_child_execution_surface(
                        &entry.child_agent,
                        &fresh_args,
                    ) {
                        Ok(fresh) => crate::engine::builtin::batch_child_concurrently_admissible(
                            &fresh,
                            entry_parent_write_admitted,
                        ),
                        // Unresolvable under the pin (e.g. the `docs` pipeline, whose
                        // stage name `load` rejects) → NOT concurrently admissible;
                        // run exclusively. The build/pipeline below surfaces any
                        // routing error.
                        Err(_) => false,
                    }
                } else {
                    concurrent
                };
                let (_read_guard, _write_guard) = if concurrent {
                    (Some(child_admission_lock.clone().read_owned().await), None)
                } else {
                    (None, Some(child_admission_lock.clone().write_owned().await))
                };
                // Whether this child holds a SHARED read guard (runs concurrently).
                // Used to re-validate the ACTUALLY-BUILT child below: a read guard is
                // safe only for a child whose real surface is still concurrently
                // admissible.
                let held_read = _read_guard.is_some();
                let mut snapshot = NoninteractiveDelegationSnapshot::empty();
                let outcome = if let Some(err) = grant_rejection(GrantRejectionInput {
                    parent_cwd: &driver.cwd,
                    cwd: &child_cwd.resolved,
                    config: &pinned,
                    parent_agent: &parent,
                    parent_vnext_grant: driver
                        .stack
                        .last()
                        .and_then(|frame| frame.agent.vnext_grant.as_ref()),
                    child_agent: &entry.child_agent,
                    grant: &entry.granted_tools,
                    assistant_db: &driver.session.db,
                    local_installations: &driver.vnext_local_installation_resolver,
                })
                .await
                {
                    DelegationChildOutcome::failed(err)
                } else if entry.child_agent == "docs" {
                    // The docs pipeline bypasses `builtin::load`, so it has
                    // no resolved child model at spawn time and intentionally
                    // emits no routing amend. The pipeline DOES return the model
                    // that authored the report, attached as `child_routing`
                    // below so the finalizer journals it through the
                    // frame-carrying path (decision 10.3) rather than frame-less
                    // `record_event`.
                    if entry.resume_handle.is_some() {
                        DelegationChildOutcome::failed(stale_handle_error(&entry.child_agent))
                    } else {
                        // Build the docs stage args under the PINNED attempt config
                        // so `resolve_child_model`, `child_llm_mode_for_model`, and
                        // the pipeline's internal `spawn_args.config` reads (Docs.1 +
                        // Docs.2) all resolve under ONE generation, consistent with
                        // the handoff expansion.
                        let docs_args = crate::engine::builtin::SpawnArgs {
                            config: pinned.clone(),
                            ..driver.spawn_args_delegated_in_cwd(
                                &child_cwd.resolved,
                                false,
                                Vec::new(),
                                entry.model.clone(),
                                child_recursion.clone(),
                            )
                        };
                        // J1: resolve the PINNED docs-resolver stage model FIRST
                        // (the per-child pin may capture a newer generation than the
                        // batch preflight validated). Fail CLOSED with the
                        // content-safe routing error — and record NO write-scope
                        // grant — if it is unresolvable under the pin, so a resolve
                        // failure never leaves an orphaned authorization side effect.
                        // Fiii: derive the docs-resolver posture and expand the
                        // entry's handoff tags UNDER it, matching the single-docs
                        // path.
                        match crate::engine::builtin::resolve_child_model(
                            "docs-resolver",
                            &docs_args,
                        ) {
                            Err(e) => DelegationChildOutcome::failed(format!("Error: {e:#}")),
                            Ok(docs_model) => {
                                let docs_llm_mode =
                                    crate::engine::builtin::child_llm_mode_for_model(
                                        &docs_args,
                                        &docs_model,
                                    );
                                let docs_brief = driver.expand_handoff_tags(
                                    &entry.prompt,
                                    &child_cwd.resolved,
                                    docs_llm_mode,
                                    &entry.child_agent,
                                );
                                // Model resolved → this is a dispatchable attempt.
                                // NOW record any write-scope grant (never before the
                                // resolve above — no grant on a fail-closed path).
                                if let Some(scope) = resolved_write_scope.as_ref() {
                                    driver.pregrant_write_scope(scope).await;
                                }
                                match crate::engine::docs_pipeline::run(
                                    &docs_brief,
                                    &docs_args,
                                    driver.session.clone(),
                                    driver.locks.clone(),
                                    driver.redact.clone(),
                                    pinned.clone(),
                                    driver.approver.clone(),
                                    driver.interrupts.clone(),
                                    child_cancel.clone(),
                                    Some(driver.tandem_set.clone()),
                                    Some(tx.clone()),
                                    Some(NoninteractiveSteerTarget::new(
                                        entry_task_call_id.clone(),
                                        entry.label.clone(),
                                    )),
                                )
                                .await
                                {
                                    Ok(report) => DelegationChildOutcome::ok(report.report)
                                        .with_child_routing(ChildRoutingMetadata::from_model(
                                            report.report_model.as_ref(),
                                        )),
                                    Err(e) => {
                                        DelegationChildOutcome::failed(format!("Error: {e:#}"))
                                    }
                                }
                            }
                        }
                    }
                } else {
                    // Build + dispatch the child under the PINNED attempt config, so
                    // its model, posture, and every downstream read share the
                    // admitted generation. The admission decision was settled under
                    // that generation (the guard is held), and the pin makes it
                    // impossible for the config to move between build and dispatch —
                    // no split, no post-build generation re-check needed.
                    let dispatch_args = crate::engine::builtin::SpawnArgs {
                        config: pinned.clone(),
                        ..driver.spawn_args_delegated_in_cwd_scoped(
                            &child_cwd.resolved,
                            false,
                            entry.granted_tools.clone(),
                            entry.model.clone(),
                            child_recursion.clone(),
                            DelegationConfinement {
                                lock_identity: Some(format!(
                                    "{}#{}",
                                    entry.child_agent, entry.label
                                )),
                                write_scope: resolved_write_scope.clone(),
                            },
                        )
                    };
                    let child =
                        match crate::engine::builtin::load(&entry.child_agent, &dispatch_args) {
                            Ok(child) => child,
                            Err(e) => {
                                return (
                                    idx,
                                    entry,
                                    DelegationChildOutcome::failed(format!("Error: {e:#}")),
                                    snapshot,
                                );
                            }
                        };
                    // K1: the guard CLASS was decided from the child's admission
                    // surface, but the child is BUILT here from a SECOND, independent
                    // resolution of its agent DEFINITION (`load` re-reads the
                    // workspace/assistant-DB, which the config pin does NOT cover). A
                    // concurrent def edit that adds `write`/`edit` between admission
                    // and this build would make the ACTUAL child write-capable while
                    // it holds the SHARED read guard it was admitted under — a
                    // concurrent-write (AC7/AC8) violation. Re-derive the BUILT
                    // child's admissibility from its real surface: if it holds a read
                    // guard but is no longer concurrently admissible (now
                    // write-capable / non-read-eligible, and it did not earn
                    // parent-write-admission), FAIL CLOSED (content-safe re-delegate)
                    // rather than dispatch a child more privileged than its held
                    // guard. The exclusive write guard runs alone, so it needs no
                    // re-check. The guard is released by RAII on this return.
                    if held_read
                        && !crate::engine::builtin::batch_child_concurrently_admissible(
                            &crate::engine::builtin::surface_for_built_child(
                                &child,
                                &dispatch_args,
                                pinned.generation(),
                            ),
                            entry_parent_write_admitted,
                        )
                    {
                        let report = format!(
                            "Error: batch entry `{}`: the child's built surface is more privileged than its admitted read-guard class (its agent definition changed between admission and build); re-delegate",
                            entry.label
                        );
                        return (idx, entry, DelegationChildOutcome::failed(report), snapshot);
                    }
                    // Record any write-scope grant under the pinned attempt config,
                    // only AFTER the built child's surface is confirmed to match its
                    // held guard (no orphaned grant on the fail-closed path above).
                    if let Some(scope) = resolved_write_scope.as_ref() {
                        driver.pregrant_write_scope(scope).await;
                    }
                    let child_routing = ChildRoutingMetadata::from_model(&child.model);
                    driver
                        .emit_subagent_routing_amend(
                            tx,
                            &entry.child_agent,
                            &entry_task_call_id,
                            &entry.label,
                            &child_routing,
                        )
                        .await;
                    let mut child_session = driver.session.clone();
                    let mut prior_history = delegation_payload_history;
                    let brief = if entry.context == crate::engine::agent::TaskContext::Fork {
                        match driver.prepare_fork_task_context().await {
                            Ok((session, history)) => {
                                child_session = session;
                                prior_history = history;
                                entry.prompt.clone()
                            }
                            Err(e) => {
                                return (
                                    idx,
                                    entry,
                                    DelegationChildOutcome::failed(format!(
                                        "Error: failed to create forked task session: {e:#}"
                                    )),
                                    snapshot,
                                );
                            }
                        }
                    } else {
                        compose_subagent_brief(&entry.prompt, &entry_why)
                    };
                    let brief = driver
                        .assign_todos_to_task(
                            brief,
                            &entry.todo_ids,
                            &entry_task_call_id,
                            &entry.label,
                            &entry.child_agent,
                        )
                        .await;
                    let brief = driver.expand_handoff_tags(
                        &brief,
                        &child_cwd.resolved,
                        child.llm_mode,
                        &entry.child_agent,
                    );
                    // Render the assembled brief for the child's resolved
                    // custody class before it leaves the parent: an untrusted
                    // (cloud) child gets the session redaction-table rendering,
                    // a trusted (self-hosted / no-log) child gets it unchanged.
                    let brief = {
                        let (extended, providers) =
                            crate::engine::model_roles::load_model_role_config(&pinned);
                        crate::engine::model_roles::render_brief_for_model(
                            &providers,
                            &child.model,
                            &extended,
                            &brief,
                        )
                    };
                    let child_hook_lifecycle = driver
                        .noninteractive_delegations
                        .child_hook_lifecycle(&entry_task_call_id, &entry.label)
                        .expect("batch child lifecycle registered before execution");
                    let child_result = run_noninteractive_resumable(
                        child,
                        brief,
                        prior_history,
                        child_session,
                        driver.locks.clone(),
                        driver.redact.clone(),
                        child_cwd.resolved.clone(),
                        pinned.clone(),
                        driver.process_containment.clone(),
                        Some(child_hook_lifecycle.clone()),
                        driver.interrupts.clone(),
                        child_cancel.clone(),
                        driver.approver.clone(),
                        driver.resource_scheduler.clone(),
                        driver.loop_guard_threshold,
                        EXPLORE_MAX_TURNS,
                        driver.vnext_local_installation_resolver.clone(),
                        Some(driver.tandem_set.clone()),
                        Some(tx.clone()),
                        Some(NoninteractiveSteerTarget::new(
                            entry_task_call_id.clone(),
                            entry.label.clone(),
                        )),
                    )
                    .await;
                    match child_result {
                        Ok(outcome) => {
                            snapshot = NoninteractiveDelegationSnapshot::from_history(
                                outcome.history.clone(),
                            );
                            let final_child_routing = child_routing
                                .clone()
                                .with_fallback_decision(outcome.fallback_decision.as_ref());
                            if outcome.fallback_decision.is_some() {
                                driver
                                    .emit_subagent_routing_amend(
                                        tx,
                                        &entry.child_agent,
                                        &entry_task_call_id,
                                        &entry.label,
                                        &final_child_routing,
                                    )
                                    .await;
                            }
                            DelegationChildOutcome::ok(outcome.report)
                                .with_child_routing(final_child_routing)
                        }
                        Err(e) => {
                            let (message, history, fallback_decision, failure_envelope) =
                                e.into_parts();
                            let partial_progress = partial_progress_from_history(&history);
                            snapshot = NoninteractiveDelegationSnapshot::from_history(history);
                            let final_child_routing = child_routing
                                .clone()
                                .with_fallback_decision(fallback_decision.as_ref());
                            if fallback_decision.is_some() {
                                driver
                                    .emit_subagent_routing_amend(
                                        tx,
                                        &entry.child_agent,
                                        &entry_task_call_id,
                                        &entry.label,
                                        &final_child_routing,
                                    )
                                    .await;
                            }
                            let outcome = match failure_envelope {
                                Some(envelope) => DelegationChildOutcome::failed_with_envelope(
                                    envelope,
                                    partial_progress,
                                ),
                                None => DelegationChildOutcome::failed_with_progress(
                                    format!("Error: {message}"),
                                    partial_progress,
                                ),
                            };
                            outcome.with_child_routing(final_child_routing)
                        }
                    }
                };
                (idx, entry, outcome, snapshot)
            };
            runs.push(child_fut);
        }

        while let Some((idx, entry, outcome, snapshot)) = runs.next().await {
            let report = self
                .reconcile_todo_delta(
                    &task_call_id,
                    &entry.label,
                    &entry.child_agent,
                    &outcome.report,
                    outcome.failed,
                )
                .await;
            let caller = self.stack.last().expect("stack never empty").agent.clone();
            let report =
                self.expand_handoff_tags(&report, &self.cwd, caller.llm_mode, &caller.name);
            let mut report_data = subagent_report_event_data(
                &entry.child_agent,
                Some(&task_call_id),
                task_provider_item_id.as_deref(),
                task_function_call_id.as_deref(),
                &entry.label,
                &report,
                Some(&outcome.partial_progress),
            );
            if let Some(files_touched) = extract_files_touched(&report) {
                report_data["files_touched"] = serde_json::to_value(files_touched)
                    .unwrap_or_else(|_| serde_json::json!({ "serialization_error": true }));
            }
            if let Some(failure) = outcome.failure.as_ref() {
                report_data["failure"] = serde_json::to_value(failure)
                    .unwrap_or_else(|_| serde_json::json!({ "serialization_error": true }));
            }
            let report_data = match outcome.child_routing.as_ref() {
                Some(routing) => with_child_routing_metadata(report_data, routing),
                None => with_model_routing_metadata(
                    report_data,
                    &self.stack.last().unwrap().agent.model,
                ),
            };
            // Child-authored report: route through the frame-carrying journaling
            // path with the child's trust + pre-policy session table (H2), so a
            // trusted child's table literal journals (or fail-closed scrubs)
            // rather than persisting raw. Untrusted → journals nothing (already
            // post-redaction). Unknown routing → plain path (today's semantics).
            let record_result = match outcome.child_routing.as_ref() {
                Some(routing) => {
                    self.session
                        .record_event_with_model_frame(
                            crate::db::session_log::SessionEventKind::SubagentReport,
                            Some(&entry.child_agent),
                            Some(&task_call_id),
                            crate::session::SessionEventModelFrame {
                                provider_id: &routing.provider,
                                model_id: &routing.model,
                                config: &self.config,
                                session_table: self.redact.as_ref(),
                            },
                            &report_data,
                        )
                        .await
                }
                None => {
                    self.session
                        .record_event(
                            crate::db::session_log::SessionEventKind::SubagentReport,
                            Some(&entry.child_agent),
                            Some(&task_call_id),
                            &report_data,
                        )
                        .await
                }
            };
            if let Err(e) = record_result {
                tracing::warn!(error = %e, "record batch subagent_report event failed");
            }
            let routing = outcome.child_routing.as_ref().cloned().unwrap_or_else(|| {
                ChildRoutingMetadata::from_model(&self.stack.last().unwrap().agent.model)
            });
            let _ = tx
                .send(TurnEvent::SubagentReport {
                    agent: entry.child_agent.clone(),
                    task_call_id: task_call_id.clone(),
                    label: entry.label.clone(),
                    report: report.clone(),
                    failed: outcome.failed,
                    model_trusted: routing.model_trusted,
                    routing: routing.routing,
                })
                .await;
            children.push(BatchChildCompletion {
                idx,
                label: entry.label,
                child_agent: entry.child_agent,
                report,
                failed: outcome.failed,
                partial_progress: outcome.partial_progress,
                snapshot,
            });
        }

        Ok(BatchNoninteractiveCompletion {
            task_call_id,
            task_provider_item_id,
            task_function_call_id,
            children,
            repair_notes,
        })
    }

    pub(in crate::engine::driver) async fn finalize_batch_noninteractive_task(
        &mut self,
        completion: BatchNoninteractiveCompletion,
        _tx: &mpsc::Sender<TurnEvent>,
    ) -> Message {
        let BatchNoninteractiveCompletion {
            task_call_id,
            task_provider_item_id,
            task_function_call_id,
            mut children,
            repair_notes,
        } = completion;

        if children.len() == 1
            && children[0].label.is_empty()
            && children[0].child_agent.is_empty()
            && children[0].failed
        {
            return crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                task_call_id,
                task_provider_item_id,
                task_function_call_id,
                "task",
                {
                    let caller = self.stack.last().expect("stack never empty").agent.clone();
                    let report =
                        prepend_task_repair_notes(children.remove(0).report, &repair_notes);
                    self.expand_handoff_tags(&report, &self.cwd, caller.llm_mode, &caller.name)
                },
            );
        }

        children.sort_by_key(|child| child.idx);
        let registry_updates: Vec<_> = children
            .iter()
            .map(|child| {
                (
                    child.label.clone(),
                    child.report.clone(),
                    child.failed,
                    child.snapshot.clone(),
                )
            })
            .collect();
        let children: Vec<_> = children
            .into_iter()
            .map(|child| {
                let mut data = serde_json::json!({
                    "label": child.label,
                    "agent": child.child_agent,
                    "failed": child.failed,
                    "report": child.report,
                });
                if !child.partial_progress.is_empty() {
                    data["partial_progress"] = serde_json::to_value(child.partial_progress)
                        .unwrap_or_else(|_| serde_json::json!({ "serialization_error": true }));
                }
                data
            })
            .collect();
        let mut body = serde_json::json!({
            "status": "completed",
            "children": children,
        });
        if !repair_notes.is_empty() {
            body["repair_notes"] = serde_json::json!(repair_notes);
        }
        let body = body.to_string();
        let result = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
            task_call_id.clone(),
            task_provider_item_id,
            task_function_call_id,
            "task",
            body,
        );
        for (label, report, failed, snapshot) in registry_updates {
            self.noninteractive_delegations
                .set_snapshot(&task_call_id, &label, snapshot);
            self.noninteractive_delegations.complete(
                &task_call_id,
                &label,
                report.clone(),
                failed,
                Some(result.clone()),
            );
            if let Err(e) = self
                .session
                .db
                .complete_task_delegation_child(&task_call_id, &label, &report, failed, None)
                .await
            {
                tracing::warn!(error = %e, task_call_id, label, "complete batch delegation child failed");
            }
            let _ = self
                .noninteractive_delegations
                .mark_delivered(&task_call_id, &label);
        }
        if let Some(parent) = self.stack.last_mut() {
            crate::engine::delegation_prompt_prune::prune_completed_delegation_prompts_with_upcoming(
                &mut parent.history,
                Some(&result),
            );
        }
        result
    }
}

/// Map a noninteractive child's terminal registry status to the `subagentStop`
/// `endReason` matcher token. A child that has NOT reached a terminal status
/// (`Running` / `Backgrounded` — e.g. a tokio-level `Err` delivered before
/// `complete()` ran) uses the caller's `fallback`. Kept next to the fire site so
/// the stop vocabulary is single-sourced and unit-testable without the async
/// hook path (`completed` / `failed` mirror the interactive precedent's
/// `completed` / `aborted`).
/// Outcome of [`Driver::claim_noninteractive_delivery`]; see that method.
enum NoninteractiveDeliveryClaim {
    First,
    AlreadyDelivered,
    NoJob,
}

impl NoninteractiveDeliveryClaim {
    fn already_delivered(&self) -> bool {
        matches!(self, Self::AlreadyDelivered)
    }

    fn fire_stops(&self) -> bool {
        matches!(self, Self::First)
    }
}

pub(in crate::engine::driver) fn noninteractive_end_reason(
    status: NoninteractiveDelegationStatus,
    fallback: &'static str,
) -> &'static str {
    match status {
        NoninteractiveDelegationStatus::Completed => "completed",
        NoninteractiveDelegationStatus::Failed => "failed",
        NoninteractiveDelegationStatus::Cancelled => "cancelled",
        NoninteractiveDelegationStatus::Lost => "lost",
        NoninteractiveDelegationStatus::Running | NoninteractiveDelegationStatus::Backgrounded => {
            fallback
        }
    }
}

pub(in crate::engine::driver) fn delegation_status_name(
    status: crate::db::task_delegations::DelegationStatus,
) -> &'static str {
    status.as_str()
}

pub(in crate::engine::driver) fn delegation_status_live(
    status: crate::db::task_delegations::DelegationStatus,
) -> bool {
    matches!(
        status,
        crate::db::task_delegations::DelegationStatus::Running
            | crate::db::task_delegations::DelegationStatus::Backgrounded
            | crate::db::task_delegations::DelegationStatus::PausedPendingTool
    )
}

pub(in crate::engine::driver) fn task_control_key(
    row: &crate::db::task_delegations::DelegationChildDetail,
) -> (String, String) {
    (row.task_call_id.clone(), row.label.clone())
}

pub(in crate::engine::driver) fn orphaned_task_control_keys(
    rows: &[crate::db::task_delegations::DelegationChildDetail],
    registry: &NoninteractiveDelegationRegistry,
) -> HashSet<(String, String)> {
    rows.iter()
        .filter(|row| {
            delegation_status_live(row.status) && !registry.is_live(&row.task_call_id, &row.label)
        })
        .map(task_control_key)
        .collect()
}

pub(in crate::engine::driver) fn task_control_actionable_live(
    row: &crate::db::task_delegations::DelegationChildDetail,
    orphaned: &HashSet<(String, String)>,
    registry: &NoninteractiveDelegationRegistry,
) -> bool {
    delegation_status_live(row.status)
        && !orphaned.contains(&task_control_key(row))
        && registry.is_live(&row.task_call_id, &row.label)
}

pub(in crate::engine::driver) fn task_control_row_status_name(
    row: &crate::db::task_delegations::DelegationChildDetail,
    orphaned: &HashSet<(String, String)>,
) -> String {
    if orphaned.contains(&task_control_key(row)) {
        "lost (orphaned)".to_string()
    } else {
        delegation_status_name(row.status).to_string()
    }
}

pub(in crate::engine::driver) fn resolve_task_control_targets(
    rows: &[crate::db::task_delegations::DelegationChildDetail],
    task_call_id: Option<String>,
    label: Option<String>,
    allow_whole_job: bool,
) -> std::result::Result<Vec<crate::db::task_delegations::DelegationChildDetail>, String> {
    let live_rows = rows
        .iter()
        .filter(|row| delegation_status_live(row.status))
        .collect::<Vec<_>>();
    let selected = match (task_call_id.as_deref(), label.as_deref()) {
        (Some(task), Some(label)) => rows
            .iter()
            .filter(|row| row.task_call_id == task && row.label == label)
            .cloned()
            .collect::<Vec<_>>(),
        (Some(task), None) if allow_whole_job => rows
            .iter()
            .filter(|row| row.task_call_id == task)
            .cloned()
            .collect::<Vec<_>>(),
        (Some(task), None) => rows
            .iter()
            .filter(|row| row.task_call_id == task)
            .cloned()
            .collect::<Vec<_>>(),
        (None, Some(label)) => {
            let matches = live_rows
                .iter()
                .filter(|row| row.label == label)
                .copied()
                .collect::<Vec<_>>();
            if matches.len() > 1 {
                return Err(format!(
                    "Error: label `{label}` is ambiguous across active delegations; pass `task_call_id`"
                ));
            }
            matches.into_iter().cloned().collect::<Vec<_>>()
        }
        (None, None) => {
            if live_rows.len() == 1 {
                vec![(*live_rows[0]).clone()]
            } else if live_rows.is_empty() {
                return Err("Error: no active task delegations".to_string());
            } else {
                return Err(
                    "Error: multiple active task delegations; pass `task_call_id` and/or `label`"
                        .to_string(),
                );
            }
        }
    };
    if selected.is_empty() {
        Err("Error: no matching task delegation".to_string())
    } else {
        Ok(selected)
    }
}

pub(in crate::engine::driver) fn task_envelope(mut value: serde_json::Value) -> String {
    if let Some(obj) = value.as_object_mut() {
        obj.insert("type".to_string(), serde_json::json!("task_delegation"));
        obj.insert("version".to_string(), serde_json::json!(1));
    }
    serde_json::to_string(&value).unwrap_or_else(|_| {
        "{\"type\":\"task_delegation\",\"version\":1,\"state\":\"serialization_error\"}".to_string()
    })
}

pub(in crate::engine::driver) fn task_child_detail_json(
    row: &crate::db::task_delegations::DelegationChildDetail,
    orphaned: &HashSet<(String, String)>,
) -> serde_json::Value {
    let is_orphaned = orphaned.contains(&task_control_key(row));
    let status = if is_orphaned {
        "lost"
    } else {
        delegation_status_name(row.status)
    };
    let report_available = row.report.is_some();
    let result_pending =
        !row.result_delivered && (!delegation_status_live(row.status) || is_orphaned);
    let actionable = delegation_status_live(row.status) && !is_orphaned;
    let mut child = serde_json::json!({
        "task_call_id": row.task_call_id,
        "label": row.label,
        "agent": row.child_agent,
        "model": row.model.as_deref().unwrap_or("default"),
        "status": status,
        "blocking": row.status == crate::db::task_delegations::DelegationStatus::Running && !is_orphaned,
        "tool_call_closed": row.status != crate::db::task_delegations::DelegationStatus::Running,
        "result_pending": result_pending,
        "report_available": report_available,
        "report_delivered": row.result_delivered,
        "pending_steers": row.pending_steers,
        "orphaned": is_orphaned,
        "actionable": actionable,
        "started_at": row.started_at,
        "finished_at": row.finished_at,
        "updated_at": row.updated_at,
    });
    if let Some(report) = &row.report {
        child["report"] = serde_json::json!(crate::text::cap_chars(report, 500).0);
    }
    child
}

pub(in crate::engine::driver) fn format_task_control_list(
    rows: &[crate::db::task_delegations::DelegationChildDetail],
    orphaned: &HashSet<(String, String)>,
) -> String {
    let children = rows
        .iter()
        .take(12)
        .map(|row| task_child_detail_json(row, orphaned))
        .collect::<Vec<_>>();
    task_envelope(serde_json::json!({
        "state": "list",
        "task_call_id": serde_json::Value::Null,
        "blocking": children.iter().any(|child| child["blocking"].as_bool().unwrap_or(false)),
        "tool_call_closed": true,
        "result_pending": children.iter().any(|child| child["result_pending"].as_bool().unwrap_or(false)),
        "report_available": children.iter().any(|child| child["report_available"].as_bool().unwrap_or(false)),
        "report_delivered": children.iter().all(|child| child["report_delivered"].as_bool().unwrap_or(false)),
        "children": children,
        "omitted_children": rows.len().saturating_sub(12),
    }))
}

pub(in crate::engine::driver) fn format_task_control_status(
    rows: &[crate::db::task_delegations::DelegationChildDetail],
    orphaned: &HashSet<(String, String)>,
) -> String {
    let children = rows
        .iter()
        .take(8)
        .map(|row| task_child_detail_json(row, orphaned))
        .collect::<Vec<_>>();
    task_envelope(serde_json::json!({
        "state": "status",
        "task_call_id": rows.first().map(|row| row.task_call_id.as_str()),
        "blocking": children.iter().any(|child| child["blocking"].as_bool().unwrap_or(false)),
        "tool_call_closed": children.iter().all(|child| child["tool_call_closed"].as_bool().unwrap_or(false)),
        "result_pending": children.iter().any(|child| child["result_pending"].as_bool().unwrap_or(false)),
        "report_available": children.iter().any(|child| child["report_available"].as_bool().unwrap_or(false)),
        "report_delivered": children.iter().all(|child| child["report_delivered"].as_bool().unwrap_or(false)),
        "children": children,
        "omitted_children": rows.len().saturating_sub(8),
    }))
}

pub(in crate::engine::driver) fn format_delegation_background_ack(
    task_call_id: &str,
    completed: &[(String, String)],
    running: &[String],
) -> String {
    let mut children = Vec::new();
    for (label, report) in completed {
        children.push(serde_json::json!({
            "task_call_id": task_call_id,
            "label": label,
            "agent": serde_json::Value::Null,
            "model": serde_json::Value::Null,
            "status": "completed",
            "blocking": false,
            "tool_call_closed": true,
            "result_pending": false,
            "report_available": true,
            "report_delivered": true,
            "pending_steers": 0,
            "orphaned": false,
            "actionable": false,
            "newly_delivered": true,
            "report": report,
        }));
    }
    for label in running {
        children.push(serde_json::json!({
            "task_call_id": task_call_id,
            "label": label,
            "agent": serde_json::Value::Null,
            "model": serde_json::Value::Null,
            "status": "backgrounded",
            "blocking": false,
            "tool_call_closed": true,
            "result_pending": true,
            "report_available": false,
            "report_delivered": false,
            "pending_steers": 0,
            "orphaned": false,
            "actionable": true,
        }));
    }
    task_envelope(serde_json::json!({
        "state": "backgrounded",
        "task_call_id": task_call_id,
        "blocking": false,
        "tool_call_closed": true,
        "result_pending": !running.is_empty(),
        "report_available": !completed.is_empty(),
        "report_delivered": completed.iter().all(|_| true) && running.is_empty(),
        "children": children,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::engine::driver) struct AsyncDelegationChildResult {
    pub(in crate::engine::driver) label: String,
    pub(in crate::engine::driver) status: String,
    pub(in crate::engine::driver) report: Option<String>,
}

pub(in crate::engine::driver) fn derive_async_delegation_status(
    children: &[AsyncDelegationChildResult],
) -> &'static str {
    if children.iter().any(|child| child.status == "failed") {
        "failed"
    } else if children.iter().any(|child| child.status == "lost") {
        "lost"
    } else if children.iter().any(|child| child.status == "cancelled") {
        "cancelled"
    } else {
        "completed"
    }
}

pub(in crate::engine::driver) fn format_async_delegation_result(
    task_call_id: &str,
    completed: &[AsyncDelegationChildResult],
    running: &[String],
) -> String {
    let status = derive_async_delegation_status(completed);
    let mut children = completed
        .iter()
        .map(|child| {
            let mut value = serde_json::json!({
                "task_call_id": task_call_id,
                "label": child.label,
                "agent": serde_json::Value::Null,
                "model": serde_json::Value::Null,
                "status": child.status,
                "blocking": false,
                "tool_call_closed": true,
                "result_pending": false,
                "report_available": child.report.is_some(),
                "report_delivered": true,
                "pending_steers": 0,
                "orphaned": child.status == "lost",
                "actionable": false,
                "newly_delivered": true,
            });
            if let Some(report) = &child.report {
                if matches!(child.status.as_str(), "failed" | "cancelled" | "lost") {
                    value["error"] = serde_json::json!(report);
                } else {
                    value["report"] = serde_json::json!(report);
                }
            }
            value
        })
        .collect::<Vec<_>>();
    for label in running {
        children.push(serde_json::json!({
            "task_call_id": task_call_id,
            "label": label,
            "agent": serde_json::Value::Null,
            "model": serde_json::Value::Null,
            "status": "backgrounded",
            "blocking": false,
            "tool_call_closed": true,
            "result_pending": true,
            "report_available": false,
            "report_delivered": false,
            "pending_steers": 0,
            "orphaned": false,
            "actionable": true,
        }));
    }
    task_envelope(serde_json::json!({
        "state": status,
        "task_call_id": task_call_id,
        "blocking": false,
        "tool_call_closed": true,
        "result_pending": false,
        "report_available": !completed.is_empty(),
        "report_delivered": true,
        "children": children,
    }))
}

pub(in crate::engine::driver) fn stale_handle_error(child_agent: &str) -> String {
    format!(
        "Error: no resumable subagent for that `resume_handle` (unknown, expired, \
         or not re-queryable). Spawn a fresh `{child_agent}` subagent instead (omit \
         `resume_handle`)."
    )
}

/// The footer appended to a re-queryable subagent's report carrying its
/// follow-up handle (GOALS §3c). Terse + machine-stable so the caller's model
/// can extract and re-use it.
pub(in crate::engine::driver) fn handle_footer(handle: &str) -> String {
    format!("\n\n[follow-up handle: {handle} — pass as `resume_handle` to re-query this subagent]")
}

/// Run a child agent's loop to completion synchronously. Used for
/// noninteractive subagents — explore primarily. Drops the child's
/// per-turn events on the floor (the parent's history already has a
/// ToolStart/End representing this call); only the final text comes
/// back. The loop is bounded by the `max_turns` parameter (each role
/// passes its own named constant — explore/docs-answerer 64, docs
/// resolver 24) to bound runaway loops; the over-limit error reports
/// that limit.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_noninteractive(
    child: Agent,
    brief: String,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    cwd: std::path::PathBuf,
    config: crate::daemon::session_worker::SessionConfigHandle,
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    max_turns: usize,
    local_installations: crate::agents::LocalInstallationResolver,
    // Model-comparison tandem (shadow) set, forwarded so the `docs` pipeline's
    // resolver/answerer turns are shadowed when the feature is on.
    tandem: Option<crate::engine::schedule::TandemSet>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    steer_target: Option<NoninteractiveSteerTarget>,
) -> Result<String> {
    // The docs pipeline (the only other caller) neither rehydrates nor needs
    // transcript context: it only needs the report text.
    let child_lifecycle = steer_target.as_ref().map(|target| {
        ChildHookLifecycle::new(
            crate::db::task_delegations::delegation_child_lifecycle_id_for_session(
                session.id,
                &target.task_call_id,
                &target.label,
            ),
        )
    });
    let out = run_noninteractive_resumable(
        child,
        brief,
        Vec::new(),
        session,
        locks,
        redact,
        cwd,
        config,
        None,
        child_lifecycle,
        interrupts,
        cancel,
        approver,
        resource_scheduler,
        loop_guard_threshold,
        max_turns,
        local_installations,
        tandem,
        event_tx,
        steer_target,
    )
    .await?;
    Ok(out.report)
}

#[derive(Debug, Clone)]
pub struct NoninteractiveSteerTarget {
    task_call_id: String,
    label: String,
}

impl NoninteractiveSteerTarget {
    pub fn new(task_call_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            task_call_id: task_call_id.into(),
            label: label.into(),
        }
    }
}

impl NoninteractiveSteerTarget {
    fn lineage(&self) -> crate::session::SessionEventLineage {
        crate::session::SessionEventLineage {
            task_call_id: self.task_call_id.clone(),
            label: self.label.clone(),
        }
    }
}

#[derive(Default)]
struct PendingNestedDeltas {
    assistant: Option<(String, String)>,
    reasoning: Option<(String, String)>,
    /// Typed display text deltas keyed by (agent, attempt_id).
    display_assistant: Option<(
        String,
        crate::engine::response_performance::AssistantAttemptId,
        String,
    )>,
    /// Typed display reasoning deltas keyed by (agent, attempt_id).
    display_reasoning: Option<(
        String,
        crate::engine::response_performance::AssistantAttemptId,
        String,
    )>,
}

impl PendingNestedDeltas {
    fn push_assistant(&mut self, agent: String, delta: String) {
        match self.assistant.as_mut() {
            Some((current_agent, current_delta)) if current_agent == &agent => {
                current_delta.push_str(&delta);
            }
            _ => {
                self.assistant = Some((agent, delta));
            }
        }
    }

    fn push_reasoning(&mut self, agent: String, delta: String) {
        match self.reasoning.as_mut() {
            Some((current_agent, current_delta)) if current_agent == &agent => {
                current_delta.push_str(&delta);
            }
            _ => {
                self.reasoning = Some((agent, delta));
            }
        }
    }

    fn push_display_assistant(
        &mut self,
        agent: String,
        attempt_id: crate::engine::response_performance::AssistantAttemptId,
        delta: String,
    ) {
        match self.display_assistant.as_mut() {
            Some((current_agent, current_attempt, current_delta))
                if current_agent == &agent && *current_attempt == attempt_id =>
            {
                current_delta.push_str(&delta);
            }
            _ => {
                self.display_assistant = Some((agent, attempt_id, delta));
            }
        }
    }

    fn push_display_reasoning(
        &mut self,
        agent: String,
        attempt_id: crate::engine::response_performance::AssistantAttemptId,
        delta: String,
    ) {
        match self.display_reasoning.as_mut() {
            Some((current_agent, current_attempt, current_delta))
                if current_agent == &agent && *current_attempt == attempt_id =>
            {
                current_delta.push_str(&delta);
            }
            _ => {
                self.display_reasoning = Some((agent, attempt_id, delta));
            }
        }
    }

    fn drain(&mut self) -> Vec<TurnEvent> {
        let mut out = Vec::new();
        if let Some((agent, attempt_id, delta)) = self.display_reasoning.take()
            && !delta.is_empty()
        {
            out.push(TurnEvent::AssistantDisplayReasoningDelta {
                agent,
                attempt_id,
                delta,
            });
        }
        if let Some((agent, attempt_id, delta)) = self.display_assistant.take()
            && !delta.is_empty()
        {
            out.push(TurnEvent::AssistantDisplayTextDelta {
                agent,
                attempt_id,
                delta,
            });
        }
        if let Some((agent, delta)) = self.reasoning.take()
            && !delta.is_empty()
        {
            out.push(TurnEvent::ReasoningDelta { agent, delta });
        }
        if let Some((agent, delta)) = self.assistant.take()
            && !delta.is_empty()
        {
            out.push(TurnEvent::AssistantTextDelta { agent, delta });
        }
        out
    }
}

fn wrap_noninteractive_child_event(
    target: &NoninteractiveSteerTarget,
    inner: TurnEvent,
) -> TurnEvent {
    TurnEvent::NestedTurn {
        task_call_id: target.task_call_id.clone(),
        label: target.label.clone(),
        parent_task_call_id: None,
        inner: Box::new(inner),
    }
}

async fn send_wrapped_noninteractive_event(
    tx: &mpsc::Sender<TurnEvent>,
    target: &NoninteractiveSteerTarget,
    event: TurnEvent,
    cancel: &tokio_util::sync::CancellationToken,
) -> bool {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => false,
        result = tx.send(wrap_noninteractive_child_event(target, event)) => result.is_ok(),
    }
}

async fn flush_nested_deltas(
    tx: &mpsc::Sender<TurnEvent>,
    target: &NoninteractiveSteerTarget,
    pending: &mut PendingNestedDeltas,
    cancel: &tokio_util::sync::CancellationToken,
) -> bool {
    for event in pending.drain() {
        if !send_wrapped_noninteractive_event(tx, target, event, cancel).await {
            return false;
        }
    }
    true
}

pub(in crate::engine::driver) fn spawn_noninteractive_event_forwarder(
    mut rx: mpsc::Receiver<TurnEvent>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    target: Option<NoninteractiveSteerTarget>,
    cancel: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (Some(event_tx), Some(target)) = (event_tx, target) else {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    event = rx.recv() => {
                        if event.is_none() {
                            break;
                        }
                    }
                }
            }
            return;
        };

        let mut pending = PendingNestedDeltas::default();
        let mut flush_interval = tokio::time::interval(Duration::from_millis(100));
        flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                maybe_event = rx.recv() => {
                    let Some(event) = maybe_event else {
                        let _ = flush_nested_deltas(&event_tx, &target, &mut pending, &cancel).await;
                        break;
                    };
                    match event {
                        TurnEvent::AssistantTextDelta { agent, delta } => {
                            pending.push_assistant(agent, delta);
                        }
                        TurnEvent::ReasoningDelta { agent, delta } => {
                            pending.push_reasoning(agent, delta);
                        }
                        TurnEvent::AssistantDisplayTextDelta {
                            agent,
                            attempt_id,
                            delta,
                        } => {
                            pending.push_display_assistant(agent, attempt_id, delta);
                        }
                        TurnEvent::AssistantDisplayReasoningDelta {
                            agent,
                            attempt_id,
                            delta,
                        } => {
                            pending.push_display_reasoning(agent, attempt_id, delta);
                        }
                        other => {
                            if !flush_nested_deltas(&event_tx, &target, &mut pending, &cancel).await {
                                break;
                            }
                            if !send_wrapped_noninteractive_event(&event_tx, &target, other, &cancel).await {
                                break;
                            }
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if !flush_nested_deltas(&event_tx, &target, &mut pending, &cancel).await {
                        break;
                    }
                }
            }
        }
    })
}

fn render_noninteractive_steers(
    steers: &[crate::db::task_delegations::TaskDelegationSteerRow],
) -> String {
    let mut out = String::from("[queued delegation steer]\n");
    for (idx, steer) in steers.iter().enumerate() {
        out.push_str(&format!(
            "{}. from {}: {}\n",
            idx + 1,
            steer.origin_principal,
            steer.body.trim()
        ));
    }
    out.push_str("\nContinue the delegated task, incorporating the queued steer above.");
    out
}

/// A finished noninteractive run: the report text plus the full transcript
/// (so the driver can persist a re-query handle, GOALS §3c).
pub(crate) struct NoninteractiveOutcome {
    /// The subagent's final text + any deferred-log section.
    pub report: String,
    /// The complete `Vec<Message>` transcript (prior history + this run),
    /// persisted as a handle for read-only noninteractive subagents in
    /// normal mode.
    pub history: Vec<Message>,
    pub fallback_decision: Option<crate::engine::agent::BackupFallbackDecision>,
}

#[derive(Debug)]
pub(crate) struct NoninteractiveRunError {
    source: anyhow::Error,
    history: Vec<Message>,
    fallback_decision: Option<crate::engine::agent::BackupFallbackDecision>,
    fallback_tried: Vec<crate::engine::agent::FailoverAttempt>,
}

impl NoninteractiveRunError {
    pub(in crate::engine::driver) fn new(
        source: anyhow::Error,
        history: Vec<Message>,
        fallback_decision: Option<crate::engine::agent::BackupFallbackDecision>,
        fallback_tried: Vec<crate::engine::agent::FailoverAttempt>,
    ) -> Self {
        Self {
            source,
            history,
            fallback_decision,
            fallback_tried,
        }
    }

    pub(in crate::engine::driver) fn into_parts(
        self,
    ) -> (
        String,
        Vec<Message>,
        Option<crate::engine::agent::BackupFallbackDecision>,
        Option<SubagentFailureEnvelope>,
    ) {
        let fallback_tried = if self.fallback_tried.is_empty() {
            self.fallback_decision
                .as_ref()
                .map(|decision| decision.fallback_tried.clone())
                .unwrap_or_default()
        } else {
            self.fallback_tried
        };
        let envelope = SubagentFailureEnvelope::from_error(&self.source, fallback_tried);
        (
            format!("{:#}", self.source),
            self.history,
            self.fallback_decision,
            envelope,
        )
    }
}

impl std::fmt::Display for NoninteractiveRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.source)
    }
}

impl std::error::Error for NoninteractiveRunError {}

async fn fire_recursive_child_abnormal_stop(
    lifecycle: Option<&ChildHookLifecycle>,
    agent: &Agent,
    session: &Session,
    cwd: &std::path::Path,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    process_containment: Option<crate::process_containment::ProcessContainmentHandle>,
    end_reason: &'static str,
) {
    let Some(lifecycle) = lifecycle.filter(|lifecycle| {
        !lifecycle.start_event_emitted && !lifecycle.emitted()
    }) else {
        return;
    };
    let snapshot = config.snapshot();
    let hook_runner = process_containment.map_or_else(
        crate::engine::agent::hooks::TokioCommandRunner::new,
        crate::engine::agent::hooks::TokioCommandRunner::with_containment,
    );
    let mut discarded = crate::engine::agent::hooks::StopGateState::default();
    let _ = crate::engine::agent::hooks::run_stop_hooks(
        &hook_runner,
        &crate::engine::agent::hooks::DefaultProcessEnv,
        snapshot.hooks(),
        crate::config::extended::hooks::HookEvent::SubagentStop,
        &agent.name,
        session.id,
        cwd,
        &session.db,
        Some(&agent.name),
        Some(&lifecycle.subagent_id),
        Some(end_reason),
        &mut discarded,
    )
    .await;
    lifecycle.publish(true);
}

/// Run a child agent's loop to completion, optionally **rehydrated** from a
/// prior transcript (`prior_history`). Returns the report + the full
/// transcript. [`run_noninteractive`] is the no-rehydrate wrapper used by the
/// `docs` pipeline.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_noninteractive_resumable(
    child: Agent,
    brief: String,
    prior_history: Vec<Message>,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    cwd: std::path::PathBuf,
    config: crate::daemon::session_worker::SessionConfigHandle,
    process_containment: Option<crate::process_containment::ProcessContainmentHandle>,
    child_lifecycle: Option<ChildHookLifecycle>,
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    max_turns: usize,
    local_installations: crate::agents::LocalInstallationResolver,
    // Model-comparison tandem (shadow) set (`model-comparison-tandem-
    // inference.md`). `Some(set)` when the session has model-comparison on, so
    // this leaf subagent's (`builder`/`explore`/`docs`) substantive turns are
    // shadowed too; `None`/empty disables it. Cheap clone per call.
    tandem: Option<crate::engine::schedule::TandemSet>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    steer_target: Option<NoninteractiveSteerTarget>,
) -> std::result::Result<NoninteractiveOutcome, NoninteractiveRunError> {
    use crate::engine::agent::turn_with_backup;

    if let Some(lifecycle) = child_lifecycle.as_ref()
        && !lifecycle.start_event_emitted
    {
        let snapshot = config.snapshot();
        let hook_runner = process_containment.clone().map_or_else(
            crate::engine::agent::hooks::TokioCommandRunner::new,
            crate::engine::agent::hooks::TokioCommandRunner::with_containment,
        );
        crate::engine::agent::hooks::run_observe_hooks(
            &hook_runner,
            &crate::engine::agent::hooks::DefaultProcessEnv,
            snapshot.hooks(),
            crate::config::extended::hooks::HookEvent::SubagentStart,
            &child.name,
            session.id,
            &cwd,
            &session.db,
            None,
            None,
            Some(&child.name),
            Some(&lifecycle.subagent_id),
            crate::engine::agent::hooks::ObserveFields::default(),
        )
        .await;
    }

    let (child_tx, child_rx) = mpsc::channel::<TurnEvent>(64);
    // Recursive vNext structural tasks need the original sender for their
    // own nested forwarder.  The current child's forwarder owns only a clone.
    let forwarder =
        spawn_noninteractive_event_forwarder(
            child_rx,
            event_tx.clone(),
            steer_target.clone(),
            cancel.clone(),
        );

    let agent = Arc::new(child);
    // A resumable vNext child is itself a delegation parent. Keep its direct
    // child admission state for this whole invocation, so a nested batch has
    // the same atomic, live-child accounting as a driver-owned batch.
    let recursive_vnext_admissions = VnextChildAdmissionRegistry::default();
    // Per-turn backup-model fallback for the subagent (`per-model-
    // backup-fallback.md`): subagents inherit the *mechanism*, resolved by the
    // same model→provider→none order against the model the subagent runs on
    // (here, its own `agent.model`). Resolved once for the run — the model is
    // fixed for the subagent's lifetime, and resolution is per-turn-equivalent
    // (the subagent always tries its primary model first each turn).
    // Owner-scoped: the subagent's backup/failover models are built from the
    // store scoped to (provider, this session's workspace), so a fallback can
    // never resolve a foreign workspace's `$secret:`.
    let backup_model = resolve_backup_model_for_session(&config, &agent.model, &session);
    let fallback_models = resolve_failover_models_for_session(&config, &agent.model, &session);
    // Rehydration: a follow-up starts from the subagent's prior transcript,
    // so it answers with full knowledge of what it already did (GOALS §3c).
    let mut history: Vec<Message> = prior_history;
    let mut next_prompt = Message::user(brief);
    let mut fallback_decision: Option<crate::engine::agent::BackupFallbackDecision> = None;
    let mut fallback_tried: Vec<crate::engine::agent::FailoverAttempt> = Vec::new();
    // The latch belongs to this concrete child job, not to the parent driver or
    // process. Rehydrated follow-ups are new originating task calls and
    // therefore receive a fresh budget; every continuation of this run shares
    // the same state.
    let mut stop_gate = crate::engine::agent::hooks::StopGateState {
        lifecycle_event_latch: child_lifecycle
            .as_ref()
            .map(|lifecycle| lifecycle.lifecycle_event_emitted.clone()),
        ..Default::default()
    };
    // A noninteractive subagent's own deferred-log (`plan.md §3d`). Agents
    // that hold `defer_to_orchestrator` get their deferred items folded into
    // the leaf report they return up; agents without it keep this buffer empty.
    let deferred_log = crate::engine::deferred::DeferredLog::new();

    for _ in 0..max_turns {
        if let Some(target) = &steer_target {
            match session
                .db
                .drain_task_delegation_steers(&target.task_call_id, &target.label)
                .await
            {
                Ok(steers) if !steers.is_empty() => {
                    history.push(next_prompt);
                    next_prompt = Message::user(render_noninteractive_steers(&steers));
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        task_call_id = %target.task_call_id,
                        label = %target.label,
                        "drain delegation steer failed"
                    );
                }
            }
        }
        // Per-round id, shared with this turn's tandem shadows.
        let call_id = uuid::Uuid::new_v4();
        let mut turn_metadata = BackupTurnMetadata::default();
        // Model-comparison tandem (shadow) set for this leaf subagent turn
        // (`builder`/`explore`/`docs`, `model-comparison-tandem-
        // inference.md`). Passed into `turn`, which dispatches the shadows from
        // the exact post-redaction body; a pure DB-only observer that never
        // enters the child's history or affects its loop. `None`/empty = off.
        let turn_future = turn_with_backup(
            &agent,
            backup_model.as_ref(),
            &fallback_models,
            &mut history,
            next_prompt,
            session.clone(),
            locks.clone(),
            redact.clone(),
            cwd.clone(),
            config.clone(),
            interrupts.clone(),
            cancel.clone(),
            approver.clone(),
            None,
            resource_scheduler.clone(),
            loop_guard_threshold,
            // A noninteractive child delegation recomposes its own fresh
            // system prompt on spawn, so it never needs the live
            // instructions-file diff injection.
            false,
            crate::skills::manage::SkillWriteOrigin::Foreground,
            None,
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            deferred_log.clone(),
            call_id,
            tandem.as_ref(),
            None,
            None,
            &child_tx,
            Some(&mut turn_metadata),
        );
        let outcome_future = async {
            if let Some(target) = &steer_target {
                crate::session::with_session_event_lineage(Some(target.lineage()), turn_future)
                    .await
            } else {
                turn_future.await
            }
        };
        let outcome = match outcome_future.await {
            Ok(outcome) => {
                if !turn_metadata.fallback_tried.is_empty() {
                    fallback_tried = turn_metadata.fallback_tried.clone();
                }
                if let Some(fallback) = turn_metadata.fallback_decision.take() {
                    fallback_decision = Some(fallback);
                }
                outcome
            }
            Err(error) => {
                if !turn_metadata.fallback_tried.is_empty() {
                    fallback_tried = turn_metadata.fallback_tried.clone();
                }
                if let Some(fallback) = turn_metadata.fallback_decision.take() {
                    fallback_decision = Some(fallback);
                }
                if let Some(failure) = crate::engine::model::as_inference_failure(&error) {
                    let match_value =
                        crate::engine::agent::hooks::error_class_match_value(&failure.class);
                    let snapshot = config.snapshot();
                    let hook_runner = process_containment.clone().map_or_else(
                        crate::engine::agent::hooks::TokioCommandRunner::new,
                        crate::engine::agent::hooks::TokioCommandRunner::with_containment,
                    );
                    crate::engine::agent::hooks::run_observe_hooks(
                        &hook_runner,
                        &crate::engine::agent::hooks::DefaultProcessEnv,
                        snapshot.hooks(),
                        crate::config::extended::hooks::HookEvent::StopFailure,
                        match_value,
                        session.id,
                        &cwd,
                        &session.db,
                        None,
                        None,
                        Some(&agent.name),
                        child_lifecycle.as_ref().map(|lifecycle| lifecycle.subagent_id.as_str()),
                        crate::engine::agent::hooks::ObserveFields {
                            error_class: Some(match_value),
                            ..Default::default()
                        },
                    )
                    .await;
                }
                fire_recursive_child_abnormal_stop(
                    child_lifecycle.as_ref(),
                    &agent,
                    &session,
                    &cwd,
                    &config,
                    process_containment.clone(),
                    "failed",
                )
                .await;
                drop(child_tx);
                let _ = forwarder.await;
                return Err(NoninteractiveRunError::new(
                    error,
                    history,
                    fallback_decision,
                    fallback_tried,
                ));
            }
        };
        match outcome {
            TurnOutcome::Continue => {
                next_prompt = history
                    .pop()
                    .expect("Continue with empty history is unreachable");
            }
            TurnOutcome::Done => {
                if let Some(lifecycle) = &child_lifecycle {
                    let snapshot = config.snapshot();
                    let hook_runner = process_containment.clone().map_or_else(
                        crate::engine::agent::hooks::TokioCommandRunner::new,
                        crate::engine::agent::hooks::TokioCommandRunner::with_containment,
                    );
                    let stop_outcome = crate::engine::agent::hooks::run_stop_hooks_cancellable(
                        &hook_runner,
                        &crate::engine::agent::hooks::DefaultProcessEnv,
                        snapshot.hooks(),
                        crate::config::extended::hooks::HookEvent::SubagentStop,
                        &agent.name,
                        session.id,
                        &cwd,
                        &session.db,
                        Some(&agent.name),
                        Some(&lifecycle.subagent_id),
                        Some("completed"),
                        &mut stop_gate,
                        &cancel,
                    )
                    .await;
                    lifecycle.publish(stop_gate.lifecycle_event_emitted);
                    if let crate::engine::agent::hooks::StopHookOutcome::Continue {
                        reason,
                        additional_context,
                    } = stop_outcome
                        && !cancel.is_cancelled()
                    {
                        next_prompt = Driver::stop_continuation_prompt(reason, additional_context);
                        continue;
                    }
                }
                if cancel.is_cancelled() {
                    fire_recursive_child_abnormal_stop(
                        child_lifecycle.as_ref(), &agent, &session, &cwd, &config,
                        process_containment.clone(), "aborted",
                    ).await;
                    drop(child_tx);
                    let _ = forwarder.await;
                    return Err(NoninteractiveRunError::new(
                        anyhow::anyhow!("subagent cancelled while consulting stop hooks"),
                        history,
                        fallback_decision,
                        fallback_tried,
                    ));
                }
                drop(child_tx);
                let _ = forwarder.await;
                // No `return` tool call: fall back to wrapping the final text
                // (envelope-holding agents only — the `docs` pipeline keeps its
                // plain answer). `None` selects the fallback path.
                let report = assemble_subagent_report(&agent, &history, &deferred_log, None);
                return Ok(NoninteractiveOutcome {
                    report,
                    history,
                    fallback_decision,
                });
            }
            TurnOutcome::Return { fields } => {
                if let Some(lifecycle) = &child_lifecycle {
                    let snapshot = config.snapshot();
                    let hook_runner = process_containment.clone().map_or_else(
                        crate::engine::agent::hooks::TokioCommandRunner::new,
                        crate::engine::agent::hooks::TokioCommandRunner::with_containment,
                    );
                    let stop_outcome = crate::engine::agent::hooks::run_stop_hooks_cancellable(
                        &hook_runner,
                        &crate::engine::agent::hooks::DefaultProcessEnv,
                        snapshot.hooks(),
                        crate::config::extended::hooks::HookEvent::SubagentStop,
                        &agent.name,
                        session.id,
                        &cwd,
                        &session.db,
                        Some(&agent.name),
                        Some(&lifecycle.subagent_id),
                        Some("completed"),
                        &mut stop_gate,
                        &cancel,
                    )
                    .await;
                    lifecycle.publish(stop_gate.lifecycle_event_emitted);
                    if let crate::engine::agent::hooks::StopHookOutcome::Continue {
                        reason,
                        additional_context,
                    } = stop_outcome
                        && !cancel.is_cancelled()
                    {
                        next_prompt = Driver::stop_continuation_prompt(reason, additional_context);
                        continue;
                    }
                }
                if cancel.is_cancelled() {
                    fire_recursive_child_abnormal_stop(
                        child_lifecycle.as_ref(), &agent, &session, &cwd, &config,
                        process_containment.clone(), "aborted",
                    ).await;
                    drop(child_tx);
                    let _ = forwarder.await;
                    return Err(NoninteractiveRunError::new(
                        anyhow::anyhow!("subagent cancelled while consulting stop hooks"),
                        history,
                        fallback_decision,
                        fallback_tried,
                    ));
                }
                drop(child_tx);
                let _ = forwarder.await;
                let report =
                    assemble_subagent_report(&agent, &history, &deferred_log, Some(&fields));
                return Ok(NoninteractiveOutcome {
                    report,
                    history,
                    fallback_decision,
                });
            }
            TurnOutcome::SpawnNoninteractive {
                child_agent,
                prompt,
                model,
                remaining_depth: _,
                why: _,
                resume_handle: _,
                cwd: requested_cwd,
                write_scope,
                context: _,
                granted_tools,
                todo_ids: _,
                repair_notes,
                task_call_id,
                task_provider_item_id,
                task_function_call_id,
            } if agent.vnext_grant.is_some() => {
                // A v2 child can itself be a noninteractive orchestrator.
                // vNext task parsing routes here rather than through the
                // legacy interactive handoff, preserving cwd and write_scope
                // for the recursive child admission.
                let parent_grant = agent.vnext_grant.as_ref().expect("guarded above").clone();
                let _vnext_admission = match recursive_vnext_admissions.try_admit(&agent, 1) {
                    Ok(permits) => permits,
                    Err(error) => {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id.clone(),
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(error, &repair_notes),
                        );
                        continue;
                    }
                };
                let child_cwd = match resolve_recursive_vnext_child_cwd(
                    requested_cwd.as_deref(),
                    &cwd,
                    &session.project_root,
                ) {
                    Ok(path) => path,
                    Err(error) => {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id.clone(),
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(format!("Error: {error}"), &repair_notes),
                        );
                        continue;
                    }
                };
                if let Some(error) = super::delegation_helpers::grant_rejection(
                    super::delegation_helpers::GrantRejectionInput {
                        parent_cwd: &cwd,
                        cwd: &child_cwd,
                        config: &config,
                        parent_agent: &agent.name,
                        parent_vnext_grant: Some(&parent_grant),
                        child_agent: &child_agent,
                        grant: &granted_tools,
                        assistant_db: &session.db,
                        local_installations: &local_installations,
                    },
                )
                .await
                {
                    next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id.clone(),
                        task_function_call_id,
                        "task",
                        prepend_task_repair_notes(error, &repair_notes),
                    );
                    continue;
                }
                let resolved_write_scope = match resolve_write_scope(
                    write_scope.as_deref(),
                    &child_cwd,
                    &session.project_root,
                ) {
                    Ok(scope) => scope,
                    Err(error) => {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id.clone(),
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(format!("Error: {error}"), &repair_notes),
                        );
                        continue;
                    }
                };
                let child_args = crate::engine::builtin::SpawnArgs {
                    model: agent.model.clone(),
                    params: crate::engine::model::ModelParams {
                        prompt_cache_key: None,
                        prompt_cache_retention: None,
                        ..agent.params.clone()
                    },
                    env_overlay: agent.env_overlay.clone(),
                    cwd: child_cwd.clone(),
                    config: config.clone(),
                    session_short_id: session.short_id.clone(),
                    assistant_identity_prefix: agent.assistant_identity_prefix.clone(),
                    model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
                    interactive: false,
                    llm_mode: agent.llm_mode,
                    model_override: None,
                    delegation_model: model,
                    delegated: true,
                    delegation_recursion:
                        crate::engine::builtin::DelegationRecursionContext::default(),
                    vnext_grant: None,
                    vnext_host_policy: Some(Arc::new(parent_grant.host_policy.clone())),
                    vnext_local_installation_resolver: local_installations.clone(),
                    parent_vnext_grant: Some(parent_grant),
                    swarm_depth: 0,
                    swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
                    granted_tools,
                    lock_identity: None,
                    write_scope: resolved_write_scope,
                    credential_store: session.provider_credential_store(&config.providers()).ok(),
                };
                let result = match crate::engine::builtin::load(&child_agent, &child_args) {
                    Ok(nested_child) => Box::pin(run_noninteractive_resumable(
                        nested_child,
                        prompt,
                        Vec::new(),
                        session.clone(),
                        locks.clone(),
                        redact.clone(),
                        child_cwd,
                        config.clone(),
                        process_containment.clone(),
                        Some(ChildHookLifecycle::new(
                            crate::db::task_delegations::delegation_child_lifecycle_id_for_session(
                                session.id,
                                &task_call_id,
                                "default",
                            ),
                        )),
                        interrupts.clone(),
                        cancel.clone(),
                        approver.clone(),
                        resource_scheduler.clone(),
                        loop_guard_threshold,
                        max_turns,
                        local_installations.clone(),
                        tandem.clone(),
                        event_tx.clone(),
                        steer_target.clone(),
                    ))
                    .await
                    .map(|outcome| outcome.report)
                    .unwrap_or_else(|error| format!("Error: {error}")),
                    Err(error) => format!("Error: {error:#}"),
                };
                next_prompt =
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "task",
                        prepend_task_repair_notes(result, &repair_notes),
                    );
            }
            TurnOutcome::SpawnNoninteractiveBatch {
                entries,
                why: _,
                repair_notes,
                task_call_id,
                task_provider_item_id,
                task_function_call_id,
            } if agent.vnext_grant.is_some() => {
                // Recursive v2 batches stay in-process rather than re-entering
                // the driver background lifecycle.  Preflight every entry before
                // admitting any slot or starting any inference, then keep the
                // whole reservation alive until each direct child completes.
                // This mirrors the driver-owned batch's all-or-nothing admission
                // while preserving the nested parent's live effective grant.
                let parent_grant = agent.vnext_grant.as_ref().expect("guarded above").clone();
                let mut prepared = Vec::with_capacity(entries.len());
                let mut rejection = None;

                for (idx, entry) in entries.into_iter().enumerate() {
                    let child_cwd = match resolve_recursive_vnext_child_cwd(
                        entry.cwd.as_deref(),
                        &cwd,
                        &session.project_root,
                    ) {
                        Ok(path) => path,
                        Err(error) => {
                            rejection = Some(format!("batch entry `{}`: {error}", entry.label));
                            break;
                        }
                    };
                    if let Some(error) = super::delegation_helpers::grant_rejection(
                        super::delegation_helpers::GrantRejectionInput {
                            parent_cwd: &cwd,
                            cwd: &child_cwd,
                            config: &config,
                            parent_agent: &agent.name,
                            parent_vnext_grant: Some(&parent_grant),
                            child_agent: &entry.child_agent,
                            grant: &entry.granted_tools,
                            assistant_db: &session.db,
                            local_installations: &local_installations,
                        },
                    )
                    .await
                    {
                        rejection = Some(format!("batch entry `{}`: {error}", entry.label));
                        break;
                    }
                    let resolved_write_scope = match resolve_write_scope(
                        entry.write_scope.as_deref(),
                        &child_cwd,
                        &session.project_root,
                    ) {
                        Ok(scope) => scope,
                        Err(error) => {
                            rejection = Some(format!("batch entry `{}`: {error}", entry.label));
                            break;
                        }
                    };
                    let child_args = crate::engine::builtin::SpawnArgs {
                        model: agent.model.clone(),
                        params: crate::engine::model::ModelParams {
                            prompt_cache_key: None,
                            prompt_cache_retention: None,
                            ..agent.params.clone()
                        },
                        env_overlay: agent.env_overlay.clone(),
                        cwd: child_cwd.clone(),
                        config: config.clone(),
                        session_short_id: session.short_id.clone(),
                        assistant_identity_prefix: agent.assistant_identity_prefix.clone(),
                        model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
                        interactive: false,
                        llm_mode: agent.llm_mode,
                        model_override: None,
                        delegation_model: entry.model.clone(),
                        delegated: true,
                        delegation_recursion:
                            crate::engine::builtin::DelegationRecursionContext::default(),
                        vnext_grant: None,
                        vnext_host_policy: Some(Arc::new(parent_grant.host_policy.clone())),
                        vnext_local_installation_resolver: local_installations.clone(),
                        parent_vnext_grant: Some(parent_grant.clone()),
                        swarm_depth: 0,
                        swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
                        granted_tools: entry.granted_tools.clone(),
                        lock_identity: None,
                        write_scope: resolved_write_scope,
                        credential_store: session
                            .provider_credential_store(&config.providers())
                            .ok(),
                    };
                    let child = match crate::engine::builtin::load(&entry.child_agent, &child_args)
                    {
                        Ok(child) => child,
                        Err(error) => {
                            rejection = Some(format!(
                                "batch entry `{}`: could not load `{}`: {error:#}",
                                entry.label, entry.child_agent
                            ));
                            break;
                        }
                    };
                    prepared.push((idx, entry, child, child_cwd));
                }

                if let Some(error) = rejection {
                    next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id.clone(),
                        task_function_call_id,
                        "task",
                        prepend_task_repair_notes(format!("Error: {error}"), &repair_notes),
                    );
                    continue;
                }
                let mut vnext_admissions = match recursive_vnext_admissions
                    .try_admit(&agent, prepared.len())
                {
                    Ok(permits) => permits,
                    Err(error) => {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                task_call_id,
                                task_provider_item_id.clone(),
                                task_function_call_id,
                                "task",
                                prepend_task_repair_notes(error, &repair_notes),
                            );
                        continue;
                    }
                };

                use futures::StreamExt as _;
                let mut runs = futures::stream::FuturesUnordered::new();
                for (idx, entry, child, child_cwd) in prepared {
                    let admission = vnext_admissions
                        .pop()
                        .expect("one vNext admission per prepared child");
                    let session = session.clone();
                    let locks = locks.clone();
                    let redact = redact.clone();
                    let config = config.clone();
                    let process_containment = process_containment.clone();
                    let interrupts = interrupts.clone();
                    let cancel = cancel.clone();
                    let approver = approver.clone();
                    let resource_scheduler = resource_scheduler.clone();
                    let local_installations = local_installations.clone();
                    let tandem = tandem.clone();
                    let event_tx = event_tx.clone();
                    let steer_target = steer_target.clone();
                    // A batch tool call is the parent correlation, not a child
                    // identity. Give every concrete recursive child its own
                    // stable lifecycle key so concurrent start/stop pairs can
                    // never collapse onto the shared batch call id.
                    let child_hook_id =
                        crate::db::task_delegations::delegation_child_lifecycle_id_for_session(
                            session.id,
                            &task_call_id,
                            &entry.label,
                        );
                    runs.push(async move {
                        // RAII releases each slot as soon as its child ends,
                        // including cancellation, errors, and panics.
                        let _admission = admission;
                        let report = Box::pin(run_noninteractive_resumable(
                            child,
                            entry.prompt,
                            Vec::new(),
                            session,
                            locks,
                            redact,
                            child_cwd,
                            config,
                            process_containment,
                            Some(ChildHookLifecycle::new(child_hook_id)),
                            interrupts,
                            cancel,
                            approver,
                            resource_scheduler,
                            loop_guard_threshold,
                            max_turns,
                            local_installations,
                            tandem,
                            event_tx,
                            steer_target,
                        ))
                        .await
                        .map(|outcome| outcome.report)
                        .unwrap_or_else(|error| format!("Error: {error}"));
                        (idx, entry.label, entry.child_agent, report)
                    });
                }
                let mut reports = Vec::new();
                while let Some(report) = runs.next().await {
                    reports.push(report);
                }
                let result = render_recursive_vnext_batch_result(reports);
                next_prompt =
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        "task",
                        prepend_task_repair_notes(result, &repair_notes),
                    );
            }
            TurnOutcome::SpawnSubagent { .. }
            | TurnOutcome::SpawnNoninteractive { .. }
            | TurnOutcome::SpawnNoninteractiveBatch { .. }
            | TurnOutcome::TaskControl { .. }
            | TurnOutcome::ToolResult { .. }
            | TurnOutcome::ScheduleAction { .. }
            | TurnOutcome::Spawn { .. } => {
                // explore is a leaf without `task`/`schedule`; this shouldn't
                // happen, but if it does we bail rather than spin (the single
                // async-job authority is the main driver, never a noninteractive
                // subagent — §22 anti-runaway).
                fire_recursive_child_abnormal_stop(
                    child_lifecycle.as_ref(), &agent, &session, &cwd, &config,
                    process_containment.clone(), "failed",
                ).await;
                drop(child_tx);
                let _ = forwarder.await;
                return Err(NoninteractiveRunError::new(
                    anyhow::anyhow!(
                        "noninteractive agent `{}` attempted to delegate or schedule a job",
                        agent.name
                    ),
                    history,
                    fallback_decision,
                    fallback_tried,
                ));
            }
        }
    }
    fire_recursive_child_abnormal_stop(
        child_lifecycle.as_ref(), &agent, &session, &cwd, &config,
        process_containment, "failed",
    ).await;
    drop(child_tx);
    let _ = forwarder.await;
    Err(NoninteractiveRunError::new(
        anyhow::anyhow!(
            "noninteractive agent `{}` exceeded {max_turns} turns",
            agent.name
        ),
        history,
        fallback_decision,
        fallback_tried,
    ))
}

#[cfg(test)]
mod vnext_child_admission_tests {
    use super::*;

    #[test]
    fn recursive_batch_child_lifecycle_ids_are_distinct_from_parent_correlation() {
        let parent = "task-call";
        let ids = (0..3)
            .map(|idx| {
                ChildHookLifecycle::new(
                    crate::db::task_delegations::delegation_child_lifecycle_id_for_session(
                        uuid::Uuid::nil(),
                        parent,
                        &format!("child-{idx}"),
                    ),
                )
            })
            .map(|lifecycle| lifecycle.subagent_id)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), 3);
        assert!(!ids.contains(parent));
    }

    #[test]
    fn agent_vnext_batch_child_admission_is_atomic_and_reusable() {
        let admissions = VnextChildAdmissionRegistry::default();
        let first = admissions.try_admit_with_key(7, 2, 1).unwrap();

        // A two-child batch cannot consume the one remaining slot and leave a
        // partial child launch behind.
        assert!(admissions.try_admit_with_key(7, 2, 2).is_err());
        let second = admissions.try_admit_with_key(7, 2, 1).unwrap();
        assert!(admissions.try_admit_with_key(7, 2, 1).is_err());

        drop(first);
        drop(second);
        assert_eq!(admissions.try_admit_with_key(7, 2, 2).unwrap().len(), 2);
    }

    #[test]
    fn agent_vnext_child_admission_race_never_exceeds_limit_and_releases() {
        let admissions = VnextChildAdmissionRegistry::default();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
        let mut workers = Vec::new();

        for _ in 0..8 {
            let admissions = admissions.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                admissions.try_admit_with_key(23, 3, 1).ok()
            }));
        }
        barrier.wait();

        let held = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(held.len(), 3);
        assert!(admissions.try_admit_with_key(23, 3, 1).is_err());

        drop(held);
        assert_eq!(admissions.try_admit_with_key(23, 3, 3).unwrap().len(), 3);
    }

    #[test]
    fn agent_vnext_nested_batch_reports_children_in_input_order() {
        let rendered = render_recursive_vnext_batch_result(vec![
            (
                2,
                "third".to_string(),
                "child-c".to_string(),
                "c".to_string(),
            ),
            (
                0,
                "first".to_string(),
                "child-a".to_string(),
                "a".to_string(),
            ),
            (
                1,
                "second".to_string(),
                "child-b".to_string(),
                "Error: b".to_string(),
            ),
        ]);
        let body: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(body["status"], "completed");
        assert_eq!(body["children"][0]["label"], "first");
        assert_eq!(body["children"][1]["label"], "second");
        assert_eq!(body["children"][2]["label"], "third");
        assert_eq!(body["children"][1]["failed"], true);
    }

    #[test]
    fn agent_vnext_nested_batch_cwd_is_resolved_per_entry_and_stays_in_workspace() {
        let workspace = tempfile::tempdir().unwrap();
        let parent = workspace.path().join("parent");
        let child = parent.join("child");
        std::fs::create_dir_all(&child).unwrap();
        let outside = tempfile::tempdir().unwrap();

        assert_eq!(
            resolve_recursive_vnext_child_cwd(Some("child"), &parent, workspace.path()).unwrap(),
            child.canonicalize().unwrap()
        );
        let error = resolve_recursive_vnext_child_cwd(
            Some(outside.path().to_str().unwrap()),
            &parent,
            workspace.path(),
        )
        .unwrap_err();
        assert!(error.contains("outside trusted workspace"), "{error}");
    }

    #[test]
    fn agent_vnext_nested_batch_applies_live_same_root_target_to_each_entry() {
        let workspace = tempfile::tempdir().unwrap();
        let child = workspace.path().join("child");
        std::fs::create_dir_all(&child).unwrap();
        let definition = crate::agents::embedded_default("Build").unwrap();
        let grant = definition
            .vnext
            .unwrap()
            .resolve_grant(&crate::agents::VnextHostPolicy::for_session_config(
                &crate::config::extended::ExtendedConfig::default(),
            ))
            .unwrap();

        let same_root =
            resolve_recursive_vnext_child_cwd(None, workspace.path(), workspace.path()).unwrap();
        let subdirectory =
            resolve_recursive_vnext_child_cwd(Some("child"), workspace.path(), workspace.path())
                .unwrap();
        assert!(grant.permits_target(workspace.path(), &same_root));
        assert!(
            !grant.permits_target(workspace.path(), &subdirectory),
            "the parent grant, not a raw child cwd, is the target authority"
        );
    }
}
