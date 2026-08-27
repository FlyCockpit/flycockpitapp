use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(in crate::engine::driver) struct NoninteractiveDelegationKey {
    pub(in crate::engine::driver) task_call_id: String,
    pub(in crate::engine::driver) label: String,
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
}

impl NoninteractiveDelegationEntry {
    pub(in crate::engine::driver) fn running(
        child_agent: String,
        snapshot: NoninteractiveDelegationSnapshot,
    ) -> Self {
        Self {
            child_agent,
            status: NoninteractiveDelegationStatus::Running,
            delivered: false,
            snapshot,
            steer_queue: std::collections::VecDeque::new(),
            completion: None,
        }
    }
}

#[derive(Default)]
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
    pub(in crate::engine::driver) fn register_running(
        &mut self,
        task_call_id: &str,
        label: &str,
        child_agent: String,
        snapshot: NoninteractiveDelegationSnapshot,
    ) {
        let key = NoninteractiveDelegationKey::new(task_call_id, label);
        self.entries.insert(
            key,
            NoninteractiveDelegationEntry::running(child_agent, snapshot),
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
    /// Present only when this exact durable executor is reconstructed after a
    /// worker crash.  The snapshot owns the real next `Message`; no recovery
    /// path projects it through text or replays the original task payload.
    pub(in crate::engine::driver) recovery: Option<RecoveredNoninteractiveTaskState>,
}

pub(in crate::engine::driver) struct RecoveredNoninteractiveTaskState {
    pub(in crate::engine::driver) agent_instance_id: uuid::Uuid,
    pub(in crate::engine::driver) label: String,
    pub(in crate::engine::driver) was_backgrounded: bool,
    pub(in crate::engine::driver) history: Vec<Message>,
    pub(in crate::engine::driver) next_prompt: Message,
    /// The persisted `(history, next_prompt)` is already after this steer’s
    /// first provider handoff. Recovery must reattach its permit/receipt, not
    /// append the user payload to history a second time.
    pub(in crate::engine::driver) late_user_steer_continuation_id: Option<uuid::Uuid>,
    pub(in crate::engine::driver) pending_recursive: Option<PendingRecursiveContinuation>,
    /// The session worker consumes the durable recovery claim only after the
    /// exact child has installed its live warm-resolver endpoint.
    pub(in crate::engine::driver) endpoint_ready: Option<
        tokio::sync::oneshot::Sender<
            std::result::Result<
                (
                    crate::engine::agent::AgentTreeEndpointGeneration,
                    tokio::sync::mpsc::Sender<crate::engine::agent::AgentTreeExecutorRequest>,
                ),
                String,
            >,
        >,
    >,
    /// Shared boot-recovery barrier.  This executor and every recursive
    /// descendant publish their exact resolver mailbox before the session
    /// worker consumes the complete durable claim set; none may enter a model
    /// turn until that acknowledgement releases this gate.
    pub(in crate::engine::driver) activation_gate: crate::engine::driver::RecoveryActivationGate,
    /// A recovered batch installs every concrete resolver mailbox before it
    /// waits for declared predecessors. The gate then preserves the original
    /// dependency DAG without a global restart barrier.
    pub(in crate::engine::driver) start_gate: Option<NoninteractiveStartGate>,
    /// Shared by a recovered root and every recursive descendant.  The worker
    /// consumes claims only after this collector has observed every exact
    /// mailbox named by the persisted waiting checkpoint.
    pub(in crate::engine::driver) endpoint_collector:
        Option<std::sync::Arc<RecoveredNoninteractiveEndpointCollector>>,
}

pub(in crate::engine::driver) struct RecoveredNoninteractiveEndpointCollector {
    endpoints: std::sync::Mutex<
        std::collections::HashMap<
            uuid::Uuid,
            (
                crate::engine::agent::AgentTreeEndpointGeneration,
                tokio::sync::mpsc::Sender<crate::engine::agent::AgentTreeExecutorRequest>,
            ),
        >,
    >,
    /// A recursive descendant can legitimately become terminal while its
    /// parent is being reconstructed (for example a revoked immutable grant
    /// is converted into the parent's durable failure result).  Terminal
    /// descendants are resolved recovery outcomes, not missing mailboxes.
    terminal: std::sync::Mutex<std::collections::HashSet<uuid::Uuid>>,
    /// Descriptor/reconstruction failures that cannot be terminalized (most
    /// importantly because an owned decision is still live) must wake the
    /// reattacher with an actionable error. Waiting for a mailbox that can
    /// never be registered would otherwise deadlock worker recovery forever.
    unrecoverable: std::sync::Mutex<std::collections::HashMap<uuid::Uuid, String>>,
    changed: tokio::sync::Notify,
}

impl RecoveredNoninteractiveEndpointCollector {
    pub(in crate::engine::driver) fn new() -> Self {
        Self {
            endpoints: std::sync::Mutex::new(std::collections::HashMap::new()),
            terminal: std::sync::Mutex::new(std::collections::HashSet::new()),
            unrecoverable: std::sync::Mutex::new(std::collections::HashMap::new()),
            changed: tokio::sync::Notify::new(),
        }
    }

    fn register(
        &self,
        agent_instance_id: uuid::Uuid,
        endpoint_generation: crate::engine::agent::AgentTreeEndpointGeneration,
        endpoint: tokio::sync::mpsc::Sender<crate::engine::agent::AgentTreeExecutorRequest>,
    ) {
        self.endpoints
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(agent_instance_id, (endpoint_generation, endpoint));
        self.changed.notify_waiters();
    }

    fn report_terminal(&self, agent_instance_id: uuid::Uuid) {
        self.terminal
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(agent_instance_id);
        self.changed.notify_waiters();
    }

    fn report_unrecoverable(&self, agent_instance_id: uuid::Uuid, error: impl Into<String>) {
        self.unrecoverable
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(agent_instance_id, error.into());
        self.changed.notify_waiters();
    }

    pub(in crate::engine::driver) async fn wait_for(
        &self,
        expected: &std::collections::BTreeSet<uuid::Uuid>,
    ) -> Result<Vec<crate::engine::driver::RecoveredNoninteractiveResolverEndpoint>> {
        loop {
            let notified = self.changed.notified();
            let ready = {
                let endpoints = self
                    .endpoints
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let terminal = self
                    .terminal
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let unrecoverable = self
                    .unrecoverable
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Some((agent_instance_id, error)) =
                    expected.iter().find_map(|agent_instance_id| {
                        unrecoverable
                            .get(agent_instance_id)
                            .map(|error| (agent_instance_id, error))
                    })
                {
                    anyhow::bail!(
                        "recovered recursive executor {agent_instance_id} cannot install a resolver mailbox: {error}"
                    );
                }
                if expected.iter().all(|agent_instance_id| {
                    endpoints.contains_key(agent_instance_id)
                        || terminal.contains(agent_instance_id)
                }) {
                    Some(
                        expected
                            .iter()
                            .filter_map(|agent_instance_id| {
                                endpoints.get(agent_instance_id).cloned().map(|(endpoint_generation, endpoint)| {
                                    crate::engine::driver::RecoveredNoninteractiveResolverEndpoint {
                                        agent_instance_id: *agent_instance_id,
                                        endpoint_generation,
                                        endpoint,
                                    }
                                })
                            })
                            .collect(),
                    )
                } else {
                    None
                }
            };
            if let Some(ready) = ready {
                return Ok(ready);
            }
            notified.await;
        }
    }
}

pub(in crate::engine::driver) struct NoninteractiveStartGate {
    dependencies: Vec<tokio::sync::watch::Receiver<bool>>,
    execution_slots: std::sync::Arc<tokio::sync::Semaphore>,
}

impl NoninteractiveStartGate {
    async fn acquire(
        mut self,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> std::result::Result<tokio::sync::OwnedSemaphorePermit, String> {
        for dependency in &mut self.dependencies {
            while !*dependency.borrow() {
                tokio::select! {
                    changed = dependency.changed() => {
                        if changed.is_err() {
                            return Err("declared batch dependency executor disappeared during recovery".to_string());
                        }
                    }
                    _ = cancel.cancelled() => {
                        return Err("recovered batch child cancelled before declared dependency completed".to_string());
                    }
                }
            }
        }
        tokio::select! {
            permit = self.execution_slots.clone().acquire_owned() => permit
                .map_err(|_| "recovered batch execution coordinator stopped".to_string()),
            _ = cancel.cancelled() => Err("recovered batch child cancelled before execution".to_string()),
        }
    }
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
    /// These members had already reached a durable terminal state before the
    /// worker crashed. Include them in the aggregate result, but never replay
    /// their terminal DB transition, hook, or report.
    pub(in crate::engine::driver) already_terminal_labels: std::collections::BTreeSet<String>,
}

struct RecoveredBatchChild {
    idx: usize,
    depends_on: Vec<String>,
    task: SingleNoninteractiveTask,
}

struct RecoveredBatchNoninteractiveTask {
    task_call_id: String,
    task_provider_item_id: Option<String>,
    task_function_call_id: Option<String>,
    repair_notes: Vec<String>,
    children: Vec<RecoveredBatchChild>,
    already_terminal: Vec<BatchChildCompletion>,
}

/// Revalidate the dependency graph copied into an immutable batch descriptor
/// before recovery rebuilds its in-memory gates. Live launch validates the
/// parsed `BatchTaskEntry` graph too, but recovery must never turn a corrupt
/// descriptor's unknown edge into an accidental non-edge (or deadlock on a
/// cycle).
fn validate_recovered_batch_dependency_descriptor(entries: &[serde_json::Value]) -> Result<()> {
    let mut dependencies = std::collections::BTreeMap::<String, Vec<String>>::new();
    for entry in entries {
        let label = entry
            .get("label")
            .and_then(serde_json::Value::as_str)
            .context("recovered batch entry has no string label")?
            .to_owned();
        let deps = entry
            .get("depends_on")
            .and_then(serde_json::Value::as_array)
            .context("recovered batch entry has no dependency snapshot")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .context("recovered batch dependency is not a string")
                    .map(str::to_owned)
            })
            .collect::<Result<Vec<_>>>()?;
        anyhow::ensure!(
            dependencies.insert(label.clone(), deps).is_none(),
            "recovered batch descriptor has duplicate label `{label}`"
        );
    }
    anyhow::ensure!(
        !dependencies.is_empty(),
        "recovered batch descriptor has no entries"
    );
    for (label, deps) in &dependencies {
        let mut seen = std::collections::BTreeSet::new();
        for dependency in deps {
            anyhow::ensure!(
                dependency != label,
                "recovered batch entry `{label}` depends on itself"
            );
            anyhow::ensure!(
                dependencies.contains_key(dependency),
                "recovered batch entry `{label}` depends on unknown label `{dependency}`"
            );
            anyhow::ensure!(
                seen.insert(dependency),
                "recovered batch entry `{label}` lists dependency `{dependency}` more than once"
            );
        }
    }
    fn visit(
        label: &str,
        dependencies: &std::collections::BTreeMap<String, Vec<String>>,
        visiting: &mut std::collections::BTreeSet<String>,
        visited: &mut std::collections::BTreeSet<String>,
    ) -> Result<()> {
        if visited.contains(label) {
            return Ok(());
        }
        anyhow::ensure!(
            visiting.insert(label.to_owned()),
            "recovered batch dependency cycle includes `{label}`"
        );
        for dependency in dependencies
            .get(label)
            .expect("recovered dependency graph was validated")
        {
            visit(dependency, dependencies, visiting, visited)?;
        }
        visiting.remove(label);
        visited.insert(label.to_owned());
        Ok(())
    }
    let mut visiting = std::collections::BTreeSet::new();
    let mut visited = std::collections::BTreeSet::new();
    for label in dependencies.keys() {
        visit(label, &dependencies, &mut visiting, &mut visited)?;
    }
    Ok(())
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
}

impl Drop for BackgroundNoninteractiveJob {
    fn drop(&mut self) {
        if !self.handle.is_finished() {
            self.handle.abort();
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
    let effective = cockpit_host::path_containment::effective_path(&requested).map_err(|err| {
        format!(
            "`write_scope` `{}` cannot be resolved inside the workspace: {err}",
            requested.display()
        )
    })?;
    if !cockpit_host::path_containment::contained_under(workspace, &effective) {
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
    if !cockpit_host::path_containment::contained_under(&workspace, &resolved) {
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
                "failed": super::is_host_failure_sentinel(report.as_str()),
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
            if cockpit_host::path_containment::contained_under(left, right)
                || cockpit_host::path_containment::contained_under(right, left)
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

    /// Persist the compatibility task result and its AgentTree terminal
    /// receipt in one database transaction.  A dependency gate is never
    /// allowed to observe an in-memory completion before this returns.
    async fn settle_task_tree_child(
        &self,
        task_call_id: &str,
        label: &str,
        outcome: crate::db::agent_tree_decisions::TaskDelegationTerminalState,
        report: Option<&str>,
    ) -> Result<bool> {
        self
            .session
            .db
            .settle_task_delegation_child_and_agent(
                self.session.id,
                task_call_id.to_string(),
                label.to_string(),
                outcome,
                report.map(str::to_owned),
                None,
                serde_json::json!({
                    "source": "task_delegation",
                    "task_call_id": task_call_id,
                    "label": label,
                    "state": match outcome {
                        crate::db::agent_tree_decisions::TaskDelegationTerminalState::Completed => "completed",
                        crate::db::agent_tree_decisions::TaskDelegationTerminalState::Failed => "failed",
                        crate::db::agent_tree_decisions::TaskDelegationTerminalState::Cancelled => "cancelled",
                    },
                })
                .to_string(),
                crate::agent_tree::system_now_unix_ms(),
                None,
            )
            .await
    }

    /// Reattach a detached child from the immutable launch descriptor and its
    /// latest persisted continuation.  This deliberately bypasses task
    /// creation, payload upsert, and `ensure_*_agent`: all three would either
    /// mint a second child or overwrite the very checkpoint being recovered.
    ///
    /// Batch jobs deliberately do not pass through this one-child launcher:
    /// their dependency coordinator owns one atomic result delivery. Treating
    /// a batch label as a stand-alone single task would let it bypass declared
    /// prerequisites and could emit a partial job result.
    pub(in crate::engine::driver) async fn reattach_noninteractive_task_child(
        &mut self,
        recovery: RecoveredNoninteractiveTaskChild,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> anyhow::Result<Vec<crate::engine::driver::RecoveredNoninteractiveResolverEndpoint>> {
        anyhow::ensure!(
            recovery.label == "default",
            "batch child recovery requires the batch executor reattacher"
        );
        let args: serde_json::Value = serde_json::from_str(&recovery.original_args_json)
            .context("parsing recovered noninteractive task launch descriptor")?;
        anyhow::ensure!(
            args.get("interactive").and_then(serde_json::Value::as_bool) == Some(false),
            "recovered task descriptor is not noninteractive"
        );
        anyhow::ensure!(
            args.get("entries").is_none(),
            "batch child recovery requires the batch executor reattacher"
        );
        let entry = &args;
        anyhow::ensure!(
            entry.get("child_agent").and_then(serde_json::Value::as_str)
                == Some(recovery.child_agent.as_str()),
            "recovered task child agent does not match its durable descriptor"
        );
        let model =
            crate::engine::model_roles::DelegationModelSelector::from_value(entry.get("model"))
                .map_err(anyhow::Error::msg)?;
        let remaining_depth = entry
            .get("remaining_depth")
            .and_then(serde_json::Value::as_u64)
            .map(|value| {
                u32::try_from(value)
                    .context("recovered noninteractive task remaining depth overflows u32")
            })
            .transpose()?;
        let granted_tools = entry
            .get("granted_tools")
            .and_then(serde_json::Value::as_array)
            .context("recovered noninteractive task has no granted-tools snapshot")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .context("recovered noninteractive granted tool is not a string")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let repair_notes = args
            .get("repair_notes")
            .and_then(serde_json::Value::as_array)
            .context("recovered noninteractive task has no repair-note snapshot")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .context("recovered noninteractive repair note is not a string")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let requested_cwd = entry
            .get("requested_cwd")
            .and_then(serde_json::Value::as_str);
        let child_cwd = self
            .resolve_child_cwd(requested_cwd)
            .map_err(anyhow::Error::msg)?;
        let child_recursion = self
            .resolve_task_recursion(&recovery.child_agent, remaining_depth, &model)
            .map_err(anyhow::Error::msg)?;
        let snapshot = parse_noninteractive_recovery_snapshot(&recovery.snapshot_json)?;
        let next_prompt = snapshot.next_prompt.clone().unwrap_or_else(|| {
            Message::user("[recovery: waiting for durable recursive child result]")
        });
        let mut expected_endpoints = std::collections::BTreeSet::new();
        expected_endpoints.insert(recovery.agent_instance_id);
        if let Some(pending) = snapshot.pending_recursive.as_ref() {
            let _ = recursive_recovery_execution_order(pending)?;
            collect_recursive_recovery_endpoint_ids(
                &self.session,
                recovery.agent_instance_id,
                &pending.children,
                &mut expected_endpoints,
            )
            .await?;
        }
        let endpoint_collector =
            std::sync::Arc::new(RecoveredNoninteractiveEndpointCollector::new());
        let (endpoint_ready, endpoint_attached) = tokio::sync::oneshot::channel();
        let task = SingleNoninteractiveTask {
            child_agent: recovery.child_agent,
            // The checkpoint owns the actual next message. `brief` exists only
            // for legacy result rendering and is never used by the recovered
            // execution path below.
            brief: recovery.payload,
            model,
            remaining_depth,
            why: args
                .get("why")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            resume_handle: entry
                .get("resume_handle")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            child_cwd,
            context: crate::engine::agent::TaskContext::from_value(entry.get("context")),
            write_scope: entry
                .get("write_scope")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            granted_tools,
            todo_ids: entry
                .get("todo_ids")
                .and_then(serde_json::Value::as_array)
                .map(|ids| {
                    ids.iter()
                        .map(|id| {
                            id.as_str()
                                .context("recovered noninteractive todo id is not a string")
                                .and_then(|id| {
                                    uuid::Uuid::parse_str(id)
                                        .context("recovered noninteractive todo id is not a UUID")
                                })
                        })
                        .collect::<anyhow::Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default(),
            child_recursion,
            repair_notes,
            task_call_id: recovery.task_call_id,
            task_provider_item_id: args
                .get("provider_item_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            task_function_call_id: args
                .get("function_call_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            recovery: Some(RecoveredNoninteractiveTaskState {
                agent_instance_id: recovery.agent_instance_id,
                label: recovery.label,
                was_backgrounded: recovery.was_backgrounded,
                history: snapshot.history,
                next_prompt,
                late_user_steer_continuation_id: snapshot.late_user_steer_continuation_id,
                pending_recursive: snapshot.pending_recursive,
                endpoint_ready: Some(endpoint_ready),
                activation_gate: recovery.activation_gate,
                start_gate: None,
                endpoint_collector: Some(endpoint_collector.clone()),
            }),
        };
        self.launch_recovered_noninteractive_task(task, tx).await?;
        endpoint_attached
            .await
            .context("recovered noninteractive task exited before installing its resolver mailbox")?
            .map_err(anyhow::Error::msg)?;
        endpoint_collector.wait_for(&expected_endpoints).await
    }

    fn recovered_noninteractive_task_from_entry(
        &self,
        recovery: crate::engine::driver::RecoveredNoninteractiveTaskChild,
        args: &serde_json::Value,
        entry: &serde_json::Value,
        endpoint_ready: tokio::sync::oneshot::Sender<
            std::result::Result<
                (
                    crate::engine::agent::AgentTreeEndpointGeneration,
                    tokio::sync::mpsc::Sender<crate::engine::agent::AgentTreeExecutorRequest>,
                ),
                String,
            >,
        >,
        endpoint_collector: std::sync::Arc<RecoveredNoninteractiveEndpointCollector>,
    ) -> anyhow::Result<SingleNoninteractiveTask> {
        anyhow::ensure!(
            entry.get("child_agent").and_then(serde_json::Value::as_str)
                == Some(recovery.child_agent.as_str()),
            "recovered batch child agent does not match its durable descriptor"
        );
        let model =
            crate::engine::model_roles::DelegationModelSelector::from_value(entry.get("model"))
                .map_err(anyhow::Error::msg)?;
        let remaining_depth = entry
            .get("remaining_depth")
            .and_then(serde_json::Value::as_u64)
            .map(|value| {
                u32::try_from(value).context("recovered task remaining depth overflows u32")
            })
            .transpose()?;
        let granted_tools = entry
            .get("granted_tools")
            .and_then(serde_json::Value::as_array)
            .context("recovered task has no granted-tools snapshot")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .context("recovered task granted tool is not a string")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let repair_notes = args
            .get("repair_notes")
            .and_then(serde_json::Value::as_array)
            .context("recovered task has no repair-note snapshot")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .context("recovered task repair note is not a string")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let child_cwd = self
            .resolve_child_cwd(
                entry
                    .get("requested_cwd")
                    .and_then(serde_json::Value::as_str),
            )
            .map_err(anyhow::Error::msg)?;
        let child_recursion = self
            .resolve_task_recursion(&recovery.child_agent, remaining_depth, &model)
            .map_err(anyhow::Error::msg)?;
        let snapshot = parse_noninteractive_recovery_snapshot(&recovery.snapshot_json)?;
        let next_prompt = snapshot.next_prompt.clone().unwrap_or_else(|| {
            Message::user("[recovery: waiting for durable recursive child result]")
        });
        Ok(SingleNoninteractiveTask {
            child_agent: recovery.child_agent,
            brief: recovery.payload,
            model,
            remaining_depth,
            why: args
                .get("why")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            resume_handle: entry
                .get("resume_handle")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            child_cwd,
            context: crate::engine::agent::TaskContext::from_value(entry.get("context")),
            write_scope: entry
                .get("write_scope")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            granted_tools,
            todo_ids: entry
                .get("todo_ids")
                .and_then(serde_json::Value::as_array)
                .map(|ids| {
                    ids.iter()
                        .map(|id| {
                            id.as_str()
                                .context("recovered task todo id is not a string")
                                .and_then(|id| {
                                    uuid::Uuid::parse_str(id)
                                        .context("recovered task todo id is not a UUID")
                                })
                        })
                        .collect::<anyhow::Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default(),
            child_recursion,
            repair_notes,
            task_call_id: recovery.task_call_id,
            task_provider_item_id: args
                .get("provider_item_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            task_function_call_id: args
                .get("function_call_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            recovery: Some(RecoveredNoninteractiveTaskState {
                agent_instance_id: recovery.agent_instance_id,
                label: recovery.label,
                was_backgrounded: recovery.was_backgrounded,
                history: snapshot.history,
                next_prompt,
                late_user_steer_continuation_id: snapshot.late_user_steer_continuation_id,
                pending_recursive: snapshot.pending_recursive,
                endpoint_ready: Some(endpoint_ready),
                activation_gate: recovery.activation_gate,
                start_gate: None,
                endpoint_collector: Some(endpoint_collector),
            }),
        })
    }

    pub(in crate::engine::driver) async fn reattach_noninteractive_task_batch(
        &mut self,
        recoveries: Vec<crate::engine::driver::RecoveredNoninteractiveTaskChild>,
        terminal_children: Vec<crate::engine::driver::RecoveredNoninteractiveTaskTerminal>,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> anyhow::Result<Vec<crate::engine::driver::RecoveredNoninteractiveResolverEndpoint>> {
        anyhow::ensure!(
            !recoveries.is_empty(),
            "recovered batch has no live children"
        );
        let task_call_id = recoveries[0].task_call_id.clone();
        let original_args_json = recoveries[0].original_args_json.clone();
        let args: serde_json::Value = serde_json::from_str(&original_args_json)
            .context("parsing recovered batch task launch descriptor")?;
        anyhow::ensure!(
            args.get("interactive").and_then(serde_json::Value::as_bool) == Some(false)
        );
        let entries = args
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .context("recovered batch task has no entries")?;
        validate_recovered_batch_dependency_descriptor(entries)?;
        let mut endpoints = Vec::with_capacity(recoveries.len());
        let mut children = Vec::with_capacity(recoveries.len());
        for recovery in recoveries {
            anyhow::ensure!(
                recovery.task_call_id == task_call_id,
                "recovered batch mixed task ids"
            );
            anyhow::ensure!(
                recovery.original_args_json == original_args_json,
                "recovered batch has divergent immutable descriptors"
            );
            let entry = entries
                .iter()
                .enumerate()
                .find(|(_, entry)| {
                    entry.get("label").and_then(serde_json::Value::as_str)
                        == Some(recovery.label.as_str())
                })
                .context("recovered batch child label is absent from immutable descriptor")?;
            let mut expected_endpoints = std::collections::BTreeSet::new();
            expected_endpoints.insert(recovery.agent_instance_id);
            let recovery_snapshot =
                parse_noninteractive_recovery_snapshot(&recovery.snapshot_json)?;
            if let Some(pending) = recovery_snapshot.pending_recursive.as_ref() {
                let _ = recursive_recovery_execution_order(pending)?;
                collect_recursive_recovery_endpoint_ids(
                    &self.session,
                    recovery.agent_instance_id,
                    &pending.children,
                    &mut expected_endpoints,
                )
                .await?;
            }
            let endpoint_collector =
                std::sync::Arc::new(RecoveredNoninteractiveEndpointCollector::new());
            let (endpoint_ready, endpoint_attached) = tokio::sync::oneshot::channel();
            let task = self.recovered_noninteractive_task_from_entry(
                recovery,
                &args,
                entry.1,
                endpoint_ready,
                endpoint_collector.clone(),
            )?;
            let agent_instance_id = task
                .recovery
                .as_ref()
                .expect("recovered task has recovery state")
                .agent_instance_id;
            children.push(RecoveredBatchChild {
                idx: entry.0,
                depends_on: entry
                    .1
                    .get("depends_on")
                    .and_then(serde_json::Value::as_array)
                    .context("recovered batch entry has no dependency snapshot")?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_owned)
                            .context("recovered batch dependency is not a string")
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?,
                task,
            });
            endpoints.push((
                agent_instance_id,
                endpoint_attached,
                endpoint_collector,
                expected_endpoints,
            ));
        }
        let terminal = terminal_children
            .into_iter()
            .filter_map(|terminal| {
                entries
                    .iter()
                    .enumerate()
                    .find(|(_, entry)| {
                        entry.get("label").and_then(serde_json::Value::as_str)
                            == Some(terminal.label.as_str())
                    })
                    .map(|(idx, _)| BatchChildCompletion {
                        idx,
                        label: terminal.label,
                        child_agent: terminal.child_agent,
                        report: terminal.report,
                        failed: terminal.failed,
                        partial_progress: DelegationPartialProgress::default(),
                        snapshot: NoninteractiveDelegationSnapshot::empty(),
                    })
            })
            .collect::<Vec<_>>();
        self.launch_recovered_batch_noninteractive_task(
            RecoveredBatchNoninteractiveTask {
                task_call_id,
                task_provider_item_id: args
                    .get("provider_item_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                task_function_call_id: args
                    .get("function_call_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                repair_notes: args
                    .get("repair_notes")
                    .and_then(serde_json::Value::as_array)
                    .map(|notes| {
                        notes
                            .iter()
                            .filter_map(|note| note.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
                children,
                already_terminal: terminal,
            },
            tx,
        )
        .await?;
        let mut attached = Vec::new();
        for (agent_instance_id, endpoint, collector, expected_endpoints) in endpoints {
            let (endpoint_generation, endpoint) = endpoint
                .await
                .context("recovered batch child exited before installing resolver mailbox")?
                .map_err(anyhow::Error::msg)?;
            collector.register(agent_instance_id, endpoint_generation, endpoint);
            attached.extend(collector.wait_for(&expected_endpoints).await?);
        }
        Ok(attached)
    }

    async fn launch_recovered_batch_noninteractive_task(
        &mut self,
        task: RecoveredBatchNoninteractiveTask,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> anyhow::Result<()> {
        let activation_gate = task
            .children
            .first()
            .and_then(|child| child.task.recovery.as_ref())
            .map(|recovery| recovery.activation_gate.clone())
            .context("recovered batch has no activation gate")?;
        let permits = self
            .admit_current_vnext_children(task.children.len())
            .map_err(anyhow::Error::msg)?;
        let task_call_id = task.task_call_id.clone();
        let task_provider_item_id = task.task_provider_item_id.clone();
        let task_function_call_id = task.task_function_call_id.clone();
        let completion_task_call_id = task_call_id.clone();
        let completion_task_provider_item_id = task_provider_item_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
        for child in &task.children {
            let recovery = child
                .task
                .recovery
                .as_ref()
                .expect("recovered batch child state");
            self.noninteractive_delegations.register_running(
                &task_call_id,
                &recovery.label,
                child.task.child_agent.clone(),
                NoninteractiveDelegationSnapshot::empty(),
            );
            if recovery.was_backgrounded {
                let _ = self
                    .noninteractive_delegations
                    .background_on_user_input(&task_call_id, &recovery.label);
            }
        }
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let handle = tokio::spawn(async move {
            let _permits = permits;
            let result = runner
                .execute_recovered_batch_noninteractive_task(task, &tx_for_task)
                .await;
            if activation_gate.is_aborted() {
                return;
            }
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
            },
        );
        Ok(())
    }

    async fn execute_recovered_batch_noninteractive_task(
        &mut self,
        task: RecoveredBatchNoninteractiveTask,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> Result<BatchNoninteractiveCompletion> {
        use futures::StreamExt as _;

        let RecoveredBatchNoninteractiveTask {
            task_call_id,
            task_provider_item_id,
            task_function_call_id,
            repair_notes,
            mut children,
            already_terminal,
        } = task;
        let active_labels = children
            .iter()
            .map(|child| {
                child
                    .task
                    .recovery
                    .as_ref()
                    .expect("recovery state")
                    .label
                    .clone()
            })
            .collect::<std::collections::HashSet<_>>();
        let completion_senders = children
            .iter()
            .map(|child| {
                let label = child
                    .task
                    .recovery
                    .as_ref()
                    .expect("recovery state")
                    .label
                    .clone();
                let (sender, _receiver) = tokio::sync::watch::channel(false);
                (label, sender)
            })
            .collect::<std::collections::HashMap<_, _>>();
        // Each child already holds one atomically admitted direct-child slot
        // for this recovered batch. Keep an execution permit per child here
        // so these gates encode only declared dependency edges: a recovery
        // must not manufacture a global barrier between independent siblings.
        let execution_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(children.len()));
        let mut runs = futures::stream::FuturesUnordered::new();
        for mut child in children.drain(..) {
            let label = child
                .task
                .recovery
                .as_ref()
                .expect("recovery state")
                .label
                .clone();
            let dependencies = child
                .depends_on
                .iter()
                .filter(|dependency| active_labels.contains(*dependency))
                .map(|dependency| {
                    completion_senders
                        .get(dependency)
                        .expect("active recovered dependency has completion signal")
                        .subscribe()
                })
                .collect::<Vec<_>>();
            child
                .task
                .recovery
                .as_mut()
                .expect("recovery state")
                .start_gate = Some(NoninteractiveStartGate {
                dependencies,
                execution_slots: execution_slots.clone(),
            });
            let completion_sender = completion_senders
                .get(&label)
                .expect("recovered child has completion signal")
                .clone();
            let activation_gate = child
                .task
                .recovery
                .as_ref()
                .expect("recovered batch child state")
                .activation_gate
                .clone();
            let mut child_runner = self.clone_for_background_noninteractive(tx);
            let child_tx = tx.clone();
            let child_task_call_id = task_call_id.clone();
            runs.push(async move {
                let outcome = child_runner
                    .execute_single_noninteractive_task(
                        child.task,
                        &child_tx,
                    tokio_util::sync::CancellationToken::new(),
                )
                .await?;
                anyhow::ensure!(
                    !activation_gate.is_aborted(),
                    "recovered batch activation was aborted before its resume claim was consumed"
                );
                child_runner
                    .settle_task_tree_child(
                        &child_task_call_id,
                        &label,
                        if outcome.failed {
                            crate::db::agent_tree_decisions::TaskDelegationTerminalState::Failed
                        } else {
                            crate::db::agent_tree_decisions::TaskDelegationTerminalState::Completed
                        },
                        Some(&outcome.report),
                    )
                    .await
                    .context("durably terminalizing recovered batch predecessor before releasing dependents")?;
                completion_sender.send_replace(true);
                Ok::<_, anyhow::Error>((child.idx, label, outcome))
            });
        }
        let mut completions = already_terminal;
        let already_terminal_labels = completions
            .iter()
            .map(|child| child.label.clone())
            .collect::<std::collections::BTreeSet<_>>();
        while let Some(outcome) = runs.next().await {
            let (idx, label, outcome) = outcome?;
            completions.push(BatchChildCompletion {
                idx,
                label,
                child_agent: outcome.child_agent,
                report: outcome.report,
                failed: outcome.failed,
                partial_progress: outcome.partial_progress,
                snapshot: outcome.snapshot,
            });
        }
        Ok(BatchNoninteractiveCompletion {
            task_call_id,
            task_provider_item_id,
            task_function_call_id,
            children: completions,
            repair_notes,
            already_terminal_labels,
        })
    }

    async fn launch_recovered_noninteractive_task(
        &mut self,
        task: SingleNoninteractiveTask,
        tx: &mpsc::Sender<TurnEvent>,
    ) -> anyhow::Result<()> {
        let activation_gate = task
            .recovery
            .as_ref()
            .map(|recovery| recovery.activation_gate.clone());
        let task_call_id = task.task_call_id.clone();
        let task_provider_item_id = task.task_provider_item_id.clone();
        let task_function_call_id = task.task_function_call_id.clone();
        let was_backgrounded = task
            .recovery
            .as_ref()
            .is_some_and(|recovery| recovery.was_backgrounded);
        let completion_task_call_id = task_call_id.clone();
        let completion_task_provider_item_id = task_provider_item_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
        let permits = self
            .admit_current_vnext_children(1)
            .map_err(anyhow::Error::msg)?;
        self.noninteractive_delegations.register_running(
            &task_call_id,
            "default",
            task.child_agent.clone(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        if was_backgrounded {
            let _ = self
                .noninteractive_delegations
                .background_on_user_input(&task_call_id, "default");
        }
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let handle = tokio::spawn(async move {
            let _permits = permits;
            let result = runner
                .execute_single_noninteractive_task(
                    task,
                    &tx_for_task,
                    tokio_util::sync::CancellationToken::new(),
                )
                .await;
            // A failed claim acknowledges no recovered work.  Suppress the
            // ordinary completion/failure finalizer so an activation abort
            // cannot turn the still-retryable durable executor into a false
            // terminal delegation outcome.
            if activation_gate.is_some_and(|gate| gate.is_aborted()) {
                return;
            }
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
            },
        );
        Ok(())
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
            "remaining_depth": task.remaining_depth,
            "why": &task.why,
            "resume_handle": &task.resume_handle,
            "context": task.context.as_str(),
            "requested_cwd": task.child_cwd.requested_json(),
            "resolved_cwd": &resolved_cwd_display,
            "write_scope": &task.write_scope,
            "granted_tools": &task.granted_tools,
            "todo_ids": &task.todo_ids,
            "repair_notes": &task.repair_notes,
            "provider_item_id": &task.task_provider_item_id,
            "function_call_id": &task.task_function_call_id,
            "interactive": false,
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
        // Publishing a task child is a two-phase durability boundary: create
        // the immutable task/payload record first, then atomically attach the
        // exact first model input, change the child to `running`, and create
        // its AgentTree lineage node in one transaction. No crash can leave a
        // running child with no reconstructable continuation or tree UUID.
        let (initial_history, initial_prompt) = if task.context
            == crate::engine::agent::TaskContext::Fork
        {
            (Vec::new(), task.brief.clone())
        } else {
            match self
                .delegation_payload_delivery(
                    &task_call_id,
                    "default",
                    &task.brief,
                    task.child_agent != "docs",
                )
                .await
            {
                Ok(delivery) => delivery,
                Err(error) => {
                    tracing::warn!(%error, %task_call_id, "preparing initial task continuation failed");
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
        };
        let initial_snapshot = match ready_noninteractive_recovery_snapshot(
            initial_history,
            Message::user(initial_prompt),
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::warn!(%error, %task_call_id, "serializing initial task continuation failed");
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
        };
        let Some(parent_agent_instance_id) =
            self.stack.last().and_then(|frame| frame.agent_instance_id)
        else {
            tracing::warn!(%task_call_id, "single task has no durable parent agent");
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
        };
        if let Err(error) = self
            .session
            .db
            .publish_task_delegation_children_and_agents(
                self.session.id,
                parent_agent_instance_id,
                task_call_id.clone(),
                vec![crate::db::agent_tree_decisions::NewTaskDelegationAgent {
                    label: "default".to_string(),
                    snapshot_json: initial_snapshot,
                }],
                crate::agent_tree::system_now_unix_ms(),
            )
            .await
        {
            tracing::warn!(%error, %task_call_id, "atomically publishing single task child and agent tree identity failed");
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
        self.noninteractive_delegations.register_running(
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
        self.fire_subagent_hook(
            crate::config::extended::hooks::HookEvent::SubagentStart,
            &task.child_agent,
            Some(&task_call_id),
            None,
        )
        .await;
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let completion_task_call_id = task_call_id.clone();
        let completion_task_provider_item_id = task_provider_item_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
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
            },
        );
        tokio::select! {
            biased;
            user = input_rx.recv() => {
                let Some(first) = user else {
                    return Ok(Message::user(""));
                };
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
                Ok(self
                    .take_backgroundable_user_interrupt(first, input_rx, tx)
                    .await)
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
            recovery,
        } = task;

        if let Some(recovery) = recovery {
            // The durable snapshot is the authority for a restarted child.
            // Do not run the normal payload-delivery/handle-rehydration path:
            // it would reconstruct a user-text prompt and lose media/tool
            // result content stored in `next_prompt`.
            self.config = self.config.repin();
            let resolved_write_scope =
                resolve_write_scope(write_scope.as_deref(), &child_cwd.resolved, &self.cwd)
                    .map_err(anyhow::Error::msg)?;
            let child = crate::engine::builtin::load(
                &child_agent,
                &self.spawn_args_delegated_in_cwd_scoped(
                    &child_cwd.resolved,
                    false,
                    granted_tools,
                    model,
                    child_recursion,
                    DelegationConfinement {
                        lock_identity: Some(format!("{child_agent}#{}", task_call_id)),
                        write_scope: resolved_write_scope,
                    },
                ),
            )
            .context("loading recovered noninteractive task child")?;
            let child_routing = ChildRoutingMetadata::from_model(&child.model);
            let recovered_next_prompt = recovery.next_prompt;
            let target = NoninteractiveSteerTarget::new(task_call_id.clone(), recovery.label)
                .with_agent_instance_id(recovery.agent_instance_id)
                .with_recovered_late_user_steer_continuation(
                    recovery.late_user_steer_continuation_id,
                );
            let outcome = run_noninteractive_resumable(
                child,
                recovered_next_prompt,
                recovery.history,
                self.session.clone(),
                self.locks.clone(),
                self.redact.clone(),
                child_cwd.resolved,
                self.config.clone(),
                self.interrupts.clone(),
                cancel,
                self.approver.clone(),
                self.resource_scheduler.clone(),
                self.loop_guard_threshold,
                EXPLORE_MAX_TURNS,
                self.vnext_local_installation_resolver.clone(),
                Some(self.tandem_set.clone()),
                Some(tx.clone()),
                Some(target),
                recovery.endpoint_ready,
                Some(recovery.activation_gate),
                recovery.start_gate,
                recovery.endpoint_collector,
                recovery.pending_recursive,
            )
            .await;
            return match outcome {
                Ok(outcome) => Ok(SingleNoninteractiveCompletion {
                    child_agent,
                    task_call_id,
                    task_provider_item_id,
                    task_function_call_id,
                    report: outcome.report,
                    failed: false,
                    failure: None,
                    partial_progress: DelegationPartialProgress::default(),
                    new_handle: None,
                    snapshot: NoninteractiveDelegationSnapshot::from_history(outcome.history),
                    shrink: None,
                    repair_notes,
                    child_routing: Some(child_routing),
                }),
                Err(error) => {
                    let (message, history, fallback_decision, failure) = error.into_parts();
                    Ok(SingleNoninteractiveCompletion {
                        child_agent,
                        task_call_id,
                        task_provider_item_id,
                        task_function_call_id,
                        report: format!("Error: {message}"),
                        failed: true,
                        failure,
                        partial_progress: DelegationPartialProgress::default(),
                        new_handle: None,
                        snapshot: NoninteractiveDelegationSnapshot::from_history(history),
                        shrink: None,
                        repair_notes,
                        child_routing: Some(
                            child_routing.with_fallback_decision(fallback_decision.as_ref()),
                        ),
                    })
                }
            };
        }

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
        let followup_enabled = crate::engine::tool::Capability::FollowupSeed
            .enabled(&crate::agents::PostureResolution::legacy(llm_mode));

        self.noninteractive_delegations.register_running(
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
                    match run_noninteractive_resumable(
                        child,
                        Message::user(dispatch_brief),
                        prior_history,
                        child_session.clone(),
                        self.locks.clone(),
                        self.redact.clone(),
                        child_cwd.resolved.clone(),
                        self.config.clone(),
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
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await
                    {
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
            let _ = self
                .settle_task_tree_child(
                    &task_call_id,
                    "default",
                    if failed {
                        crate::db::agent_tree_decisions::TaskDelegationTerminalState::Failed
                    } else {
                        crate::db::agent_tree_decisions::TaskDelegationTerminalState::Completed
                    },
                    Some(&report),
                )
                .await;
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
        let _ = self
            .settle_task_tree_child(
                &task_call_id,
                "default",
                if failed {
                    crate::db::agent_tree_decisions::TaskDelegationTerminalState::Failed
                } else {
                    crate::db::agent_tree_decisions::TaskDelegationTerminalState::Completed
                },
                Some(&report),
            )
            .await;
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
            agent_instance_id: self.stack.last().and_then(|frame| frame.agent_instance_id),
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

    /// Fire the `subagentStop` for every NONINTERACTIVE child under
    /// `task_call_id`, at the delegation-complete / delivery boundary — the
    /// single exactly-once firing per started child, paired 1:1 with the
    /// `subagentStart` fired at `register_running`. Routed through the unified
    /// [`Driver::fire_terminal_subagent_stop`] G::Stop dispatcher rather than an
    /// observe fire: a delivered noninteractive child has already terminated (its
    /// `run_noninteractive_resumable` task returned), so its stop can carry no
    /// continuation — honoring block/continue for noninteractive children is a
    /// deferred follow-up. Fires for EVERY child (including the `docs` pipeline
    /// child and any pre-loop synthetic-failed completion, which never run a
    /// gate) — this boundary is the sole firing, so there is no double.
    ///
    /// Called only from the delivered-transition arms of
    /// [`Self::finalize_background_noninteractive_completion`] (guarded by
    /// `first_delivery.fire_stops()`), so it runs once per delivered job.
    /// `endReason` reflects each child's terminal registry status;
    /// `subagentType` is the child agent type, `subagentId` is the shared
    /// delegating `task` call id.
    async fn fire_noninteractive_subagent_stops(&self, task_call_id: &str, fallback: &'static str) {
        // Collect first so no borrow of the registry is held across the await in
        // `fire_terminal_subagent_stop`. Stable order (by label) for
        // deterministic firing.
        let mut children: Vec<(String, String, &'static str)> = self
            .noninteractive_delegations
            .entries
            .iter()
            .filter(|(key, _)| key.task_call_id == task_call_id)
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
            self.fire_terminal_subagent_stop(&child_agent, Some(task_call_id), end_reason)
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
                    // `subagentStop` for the delivered NONINTERACTIVE child — the
                    // single exactly-once firing, on the tracked first delivery
                    // (a cancelled+aborted job fires its stop on the cancel path
                    // instead, and a re-delivered completion never reaches here).
                    // Fired even if `finalize_single_*` errored, so a scan/expand
                    // failure can't drop the stop; on that error the entry is
                    // un-`complete()`d and falls back to `failed`. Pairs the
                    // `subagentStart` fired at register-running.
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
                        self.settle_live_noninteractive_children_failed(&task_call_id, &body)
                            .await;
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .await
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        // Inline runtime failure: settle the child to Failed
                        // (DB + registry) so `task.control` does not report a
                        // dead child as running, then mark it delivered (the
                        // error is returned inline as the tool result). The
                        // backgrounded arm above already does this via
                        // `async_delegation_result`; the inline arm previously
                        // did neither, leaving the child stuck `Running`.
                        self.settle_live_noninteractive_children_failed(&task_call_id, &body)
                            .await;
                        if let Err(e) = self
                            .session
                            .db
                            .mark_task_delegation_child_delivered(&task_call_id, "default")
                            .await
                        {
                            tracing::warn!(error = %e, task_call_id, "mark failed inline single delegation delivered failed");
                        }
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
                        self.settle_live_noninteractive_children_failed(&task_call_id, &body)
                            .await;
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .await
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        // Inline runtime failure: settle every batch child to
                        // Failed (DB + registry) so `task.control` does not
                        // report dead children as running, then mark them
                        // delivered (the error is returned inline as the tool
                        // result). Previously the inline arm did neither.
                        self.settle_live_noninteractive_children_failed(&task_call_id, &body)
                            .await;
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
                                        tracing::warn!(error = %e, task_call_id, label = %row.label, "mark failed inline batch delegation delivered failed");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, task_call_id, "load failed inline batch delegation rows failed");
                            }
                        }
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

    /// Settle every still-live child of `task_call_id` to `Failed` in the DB
    /// and the in-memory registry, with `body` as the failure report. Called
    /// when a delegation's spawned task itself returned `Err` (so no child was
    /// `complete()`d), for BOTH backgrounded and inline delegations — otherwise
    /// an inline runtime failure would leave the child stuck `Running`, and
    /// `task.control` would report a dead child as running.
    pub(in crate::engine::driver) async fn settle_live_noninteractive_children_failed(
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
            let _ = self
                .settle_task_tree_child(
                    task_call_id,
                    &row.label,
                    crate::db::agent_tree_decisions::TaskDelegationTerminalState::Failed,
                    Some(body),
                )
                .await;
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
                "recovering durable executor; retry when its worker attaches".to_string()
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
                    && let Some(job) = self.noninteractive_jobs.remove(&task_call_id)
                {
                    job.handle.abort();
                    self.release_noninteractive_child_locks(&selected).await;
                    // `subagentStop` for each STARTED child of the aborted job. The
                    // job was removed+aborted, so its completion never reaches
                    // `finalize_background_noninteractive_completion` to fire the
                    // paired stop — fire it here with `endReason: cancelled`. Only
                    // live (still-running) entries are started-and-unpaired; an
                    // already-delivered child has a terminal status and fired its
                    // stop at delivery. This whole-job-abort path is the ONLY cancel
                    // site that fires: a per-label cancel does NOT abort the job, so
                    // that child's completion still flows through the delivery
                    // funnel and is paired there (no double stop).
                    for row in &selected {
                        if self
                            .noninteractive_delegations
                            .is_live(&row.task_call_id, &row.label)
                        {
                            // A live (aborted) child never completed, so its loop
                            // gate never ran; fire the TERMINAL `subagentStop`
                            // (`cancelled`) through the unified G::Stop dispatcher.
                            self.fire_terminal_subagent_stop(
                                &row.child_agent,
                                Some(&row.task_call_id),
                                "cancelled",
                            )
                            .await;
                        }
                    }
                }
                let mut changed = Vec::new();
                let mut unchanged = Vec::new();
                let mut recovering = Vec::new();
                for row in selected {
                    let key = task_control_key(&row);
                    if orphaned.contains(&key) {
                        // A restart leaves this durable child recoverable. Do
                        // not reinterpret a human cancel as evidence that it
                        // was lost: recovery owns reattachment and preserves
                        // any pending decision/approved-effect receipt.
                        recovering.push(format!("{}:{}", row.task_call_id, row.label));
                        continue;
                    }
                    let live_changed = self
                        .noninteractive_delegations
                        .cancel(&row.task_call_id, &row.label);
                    let db_changed = match self
                        .settle_task_tree_child(
                            &row.task_call_id,
                            &row.label,
                            crate::db::agent_tree_decisions::TaskDelegationTerminalState::Cancelled,
                            None,
                        )
                        .await
                    {
                        Ok(changed) => changed,
                        Err(e) => {
                            return format!(
                                "Error: could not atomically cancel `{}`/`{}`: {e:#}",
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
                let state = if changed.is_empty() && recovering.is_empty() {
                    "no_change"
                } else if !recovering.is_empty() && changed.is_empty() {
                    "recovering"
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
                    "recovering": recovering,
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
                        "recovering durable executor; retry when its worker attaches".to_string()
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
                        value["report"] =
                            serde_json::json!(cockpit_host::text::cap_chars(report, 1200).0);
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
                    "report": cockpit_host::text::cap_chars(&report, 1200).0,
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
                        "recovering durable executor; retry when its worker attaches".to_string()
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
                "depends_on": &entry.depends_on,
                "child_agent": &entry.child_agent,
                "model": model_selector_json(&entry.model),
                "remaining_depth": entry.remaining_depth,
                "context": entry.context.as_str(),
                "resume_handle": &entry.resume_handle,
                "requested_cwd": child_cwd.requested_json(),
                "resolved_cwd": child_cwd.resolved_display(),
                "write_scope": &entry.write_scope,
                "granted_tools": &entry.granted_tools,
                "todo_ids": &entry.todo_ids,
            })).collect::<Vec<_>>(),
            "why": &task.why,
            "repair_notes": &task.repair_notes,
            "provider_item_id": &task.task_provider_item_id,
            "function_call_id": &task.task_function_call_id,
            "interactive": false,
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
        // Keep a recovered batch all-or-nothing before any AgentTree child is
        // made running. Each snapshot records the exact first turn for that
        // label; the database publishes every label and every lineage mapping
        // in one transaction so a crash cannot produce a partially
        // addressable dependency graph.
        let mut initial_snapshots = Vec::with_capacity(task.entries.len());
        for entry in &task.entries {
            let (initial_history, initial_prompt) = if entry.context
                == crate::engine::agent::TaskContext::Fork
            {
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
                    Err(error) => {
                        tracing::warn!(%error, %task_call_id, label = %entry.label, "preparing initial batch continuation failed");
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
            };
            let snapshot = match ready_noninteractive_recovery_snapshot(
                initial_history,
                Message::user(initial_prompt),
            ) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    tracing::warn!(%error, %task_call_id, label = %entry.label, "serializing initial batch continuation failed");
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
            };
            initial_snapshots.push((entry.label.clone(), snapshot));
        }
        let Some(parent_agent_instance_id) =
            self.stack.last().and_then(|frame| frame.agent_instance_id)
        else {
            tracing::warn!(%task_call_id, "batch task has no durable parent agent");
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
        };
        let tree_children = initial_snapshots
            .into_iter()
            .map(
                |(label, snapshot_json)| crate::db::agent_tree_decisions::NewTaskDelegationAgent {
                    label,
                    snapshot_json,
                },
            )
            .collect();
        if let Err(error) = self
            .session
            .db
            .publish_task_delegation_children_and_agents(
                self.session.id,
                parent_agent_instance_id,
                task_call_id.clone(),
                tree_children,
                crate::agent_tree::system_now_unix_ms(),
            )
            .await
        {
            tracing::warn!(%error, %task_call_id, "atomically publishing batch task children and agent tree identities failed");
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
        for entry in &task.entries {
            self.noninteractive_delegations.register_running(
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
            self.fire_subagent_hook(
                crate::config::extended::hooks::HookEvent::SubagentStart,
                &entry.child_agent,
                Some(&task_call_id),
                None,
            )
            .await;
        }
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let completion_task_call_id = task_call_id.clone();
        let completion_task_provider_item_id = task_provider_item_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
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
            },
        );
        tokio::select! {
            biased;
            user = input_rx.recv() => {
                let Some(first) = user else {
                    return Ok(Message::user(""));
                };
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
                Ok(self
                    .take_backgroundable_user_interrupt(first, input_rx, tx)
                    .await)
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
                .enabled(&crate::agents::PostureResolution::legacy(parent_request_llm_mode))
        {
            batch_refusal = Some(
                "parallel write-capable task batches require the `scopedParallelWrite` capability on this agent; use sequential delegation instead"
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
                already_terminal_labels: std::collections::BTreeSet::new(),
            });
        }
        // NOTE: `pregrant_write_scope` is DEFERRED into each child's future, AFTER
        // that child's post-build generation guard (non-docs) / pre-dispatch docs
        // guard, so a mid-wait generation move never records a lingering
        // write-scope grant for a child that then fails closed.
        for entry in &entries {
            self.noninteractive_delegations.register_running(
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
        // Every child is admitted to the executor immediately. A child with
        // declared predecessors awaits *only* those completion signals inside
        // its own future, so independent siblings retain normal concurrency.
        // The edge set was validated before persistence and is persisted in the
        // job transaction; these in-memory watches merely enforce the current
        // attempt's order.
        let dependency_completion_senders = entries
            .iter()
            .map(|entry| {
                let (sender, _receiver) = tokio::sync::watch::channel(false);
                (entry.label.clone(), sender)
            })
            .collect::<std::collections::HashMap<_, _>>();
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
            let completion_sender = dependency_completion_senders
                .get(&entry.label)
                .expect("every batch entry has a completion signal")
                .clone();
            let dependency_receivers = entry
                .depends_on
                .iter()
                .map(|label| {
                    dependency_completion_senders
                        .get(label)
                        .expect("batch dependency labels were validated")
                        .subscribe()
                })
                .collect::<Vec<_>>();
            let driver = &*self;
            let entry_why = why.clone();
            let entry_task_call_id = task_call_id.clone();
            let parent = self.stack.last().unwrap().agent.name.clone();
            let (delegation_payload_history, delivered_prompt) = if entry.context
                == crate::engine::agent::TaskContext::Fork
            {
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
                        let refusal = DELEGATION_PAYLOAD_REFUSAL.to_string();
                        self.settle_task_tree_child(
                                &task_call_id,
                                &entry.label,
                                crate::db::agent_tree_decisions::TaskDelegationTerminalState::Failed,
                                Some(&refusal),
                            )
                            .await
                            .context("durably terminalizing failed batch payload before releasing dependents")?;
                        completion_sender.send_replace(true);
                        children.push(BatchChildCompletion {
                            idx,
                            label: entry.label,
                            child_agent: entry.child_agent,
                            report: refusal,
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
                let mut snapshot = NoninteractiveDelegationSnapshot::empty();
                for mut dependency_complete in dependency_receivers {
                    while !*dependency_complete.borrow() {
                        tokio::select! {
                            changed = dependency_complete.changed() => {
                                if changed.is_err() {
                                    return (
                                        idx,
                                        entry,
                                        DelegationChildOutcome::failed(
                                            "Error: declared batch dependency executor disappeared",
                                        ),
                                        snapshot,
                                        completion_sender,
                                    );
                                }
                            }
                            _ = child_cancel.cancelled() => {
                                    return (
                                        idx,
                                        entry,
                                        DelegationChildOutcome::failed(
                                            "Error: batch child cancelled before declared dependency completed",
                                        ),
                                        snapshot,
                                        completion_sender,
                                    );
                            }
                        }
                    }
                }
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
                                    completion_sender,
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
                        return (
                            idx,
                            entry,
                            DelegationChildOutcome::failed(report),
                            snapshot,
                            completion_sender,
                        );
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
                                    completion_sender,
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
                    match run_noninteractive_resumable(
                        child,
                        Message::user(brief),
                        prior_history,
                        child_session,
                        driver.locks.clone(),
                        driver.redact.clone(),
                        child_cwd.resolved.clone(),
                        pinned.clone(),
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
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await
                    {
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
                (idx, entry, outcome, snapshot, completion_sender)
            };
            runs.push(child_fut);
        }

        while let Some((idx, entry, outcome, snapshot, completion_sender)) = runs.next().await {
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
            // This durable transition is the dependency linearization point.
            // A successor may start only after both the compatibility result
            // and this exact AgentTree executor's terminal receipt commit.
            // Returning an error leaves its watch closed, so no dependent can
            // mistake an unpersisted in-memory result for a predecessor.
            self.settle_task_tree_child(
                &task_call_id,
                &entry.label,
                if outcome.failed {
                    crate::db::agent_tree_decisions::TaskDelegationTerminalState::Failed
                } else {
                    crate::db::agent_tree_decisions::TaskDelegationTerminalState::Completed
                },
                Some(&report),
            )
            .await
            .context("durably terminalizing batch predecessor before releasing dependents")?;
            completion_sender.send_replace(true);
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
            already_terminal_labels: std::collections::BTreeSet::new(),
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
            already_terminal_labels,
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
            if already_terminal_labels.contains(&label) {
                continue;
            }
            self.noninteractive_delegations
                .set_snapshot(&task_call_id, &label, snapshot);
            self.noninteractive_delegations.complete(
                &task_call_id,
                &label,
                report.clone(),
                failed,
                Some(result.clone()),
            );
            let _ = self
                .settle_task_tree_child(
                    &task_call_id,
                    &label,
                    if failed {
                        crate::db::agent_tree_decisions::TaskDelegationTerminalState::Failed
                    } else {
                        crate::db::agent_tree_decisions::TaskDelegationTerminalState::Completed
                    },
                    Some(&report),
                )
                .await;
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
        child["report"] = serde_json::json!(cockpit_host::text::cap_chars(report, 500).0);
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
    let out = run_noninteractive_resumable(
        child,
        Message::user(brief),
        Vec::new(),
        session,
        locks,
        redact,
        cwd,
        config,
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
        None,
        None,
        None,
        None,
        None,
    )
    .await?;
    Ok(out.report)
}

#[derive(Debug, Clone)]
pub struct NoninteractiveSteerTarget {
    task_call_id: String,
    label: String,
    /// Recursive vNext children do not share their compatibility task row.
    /// Their exact durable AgentTree UUID is threaded explicitly so late
    /// steers, resolver routing, and recovery cannot collapse onto the parent.
    agent_instance_id: Option<uuid::Uuid>,
    /// Only set by a recovered snapshot which already captured the first
    /// provider handoff of this exact accepted continuation.
    late_user_steer_continuation_id: Option<uuid::Uuid>,
}

impl NoninteractiveSteerTarget {
    pub fn new(task_call_id: impl Into<String>, label: impl Into<String>) -> Self {
        Self {
            task_call_id: task_call_id.into(),
            label: label.into(),
            agent_instance_id: None,
            late_user_steer_continuation_id: None,
        }
    }

    fn with_agent_instance_id(mut self, agent_instance_id: uuid::Uuid) -> Self {
        self.agent_instance_id = Some(agent_instance_id);
        self
    }

    fn with_recovered_late_user_steer_continuation(
        mut self,
        continuation_id: Option<uuid::Uuid>,
    ) -> Self {
        self.late_user_steer_continuation_id = continuation_id;
        self
    }
}

async fn terminalize_recursive_noninteractive_agent(
    session: &Session,
    agent_instance_id: uuid::Uuid,
    failed: bool,
) {
    let next_state = if failed {
        crate::db::agent_tree_decisions::AgentInstanceState::Failed
    } else {
        crate::db::agent_tree_decisions::AgentInstanceState::Completed
    };
    for _ in 0..4 {
        let agent = match session
            .db
            .agent_instance(session.id, agent_instance_id)
            .await
        {
            Ok(Some(agent)) => agent,
            Ok(None) => return,
            Err(error) => {
                tracing::warn!(%error, %agent_instance_id, "loading recursive child lifecycle row failed");
                return;
            }
        };
        if agent.state.is_terminal() {
            return;
        }
        match session
            .db
            .transition_agent_instance(
                session.id,
                agent_instance_id,
                agent.revision,
                next_state,
                r#"{"source":"recursive_noninteractive"}"#,
                crate::agent_tree::system_now_unix_ms(),
            )
            .await
        {
            Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::Transitioned(_))
            | Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::AlreadyTerminal(_)) => {
                return;
            }
            Ok(crate::db::agent_tree_decisions::AgentTransitionOutcome::RevisionConflict) => {
                continue;
            }
            Err(error) => {
                tracing::warn!(%error, %agent_instance_id, "terminalizing recursive child lifecycle row failed");
                return;
            }
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
) -> bool {
    tx.send(wrap_noninteractive_child_event(target, event))
        .await
        .is_ok()
}

/// Guarantees that a noninteractive warm endpoint is withdrawn when any of
/// this function's many terminal paths returns. Its private unbounded ingress
/// decouples `Drop` from the bounded display/event channel, so backpressure
/// cannot leave a dead mailbox in the worker's exact-owner registry. If the
/// worker has already gone away the pump observes its closed receiver, at
/// which point no registry remains to route through.
struct NoninteractiveAgentTreeEndpointRegistration {
    /// An unbounded, endpoint-private teardown lane. `Drop` can always append
    /// to it even while the bounded worker event queue is full; its dedicated
    /// pump owns the awaited delivery and preserves the exact detach until the
    /// worker goes away.
    cleanup_tx: mpsc::UnboundedSender<TurnEvent>,
    agent_instance_id: uuid::Uuid,
    endpoint_generation: crate::engine::agent::AgentTreeEndpointGeneration,
}

impl Drop for NoninteractiveAgentTreeEndpointRegistration {
    fn drop(&mut self) {
        // `UnboundedSender::send` fails only after the receiver/pump has
        // already gone away. Unlike `try_send` on the bounded worker channel,
        // a full event queue can never strand this exact-owner registry entry.
        let _ = self
            .cleanup_tx
            .send(TurnEvent::AgentTreeExecutorEndpointDetached {
                agent_instance_id: self.agent_instance_id,
                endpoint_generation: self.endpoint_generation,
            });
    }
}

async fn flush_nested_deltas(
    tx: &mpsc::Sender<TurnEvent>,
    target: &NoninteractiveSteerTarget,
    pending: &mut PendingNestedDeltas,
) -> bool {
    for event in pending.drain() {
        if !send_wrapped_noninteractive_event(tx, target, event).await {
            return false;
        }
    }
    true
}

pub(in crate::engine::driver) fn spawn_noninteractive_event_forwarder(
    mut rx: mpsc::Receiver<TurnEvent>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    target: Option<NoninteractiveSteerTarget>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (Some(event_tx), Some(target)) = (event_tx, target) else {
            while rx.recv().await.is_some() {}
            return;
        };

        let mut pending = PendingNestedDeltas::default();
        let mut flush_interval = tokio::time::interval(Duration::from_millis(100));
        flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                maybe_event = rx.recv() => {
                    let Some(event) = maybe_event else {
                        let _ = flush_nested_deltas(&event_tx, &target, &mut pending).await;
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
                            if !flush_nested_deltas(&event_tx, &target, &mut pending).await {
                                break;
                            }
                            if !send_wrapped_noninteractive_event(&event_tx, &target, other).await {
                                break;
                            }
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if !flush_nested_deltas(&event_tx, &target, &mut pending).await {
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

/// Render AgentTree late steers only after this exact child has claimed their
/// durable delivery receipt.  These are intentionally not fed through the
/// legacy task-steer queue: that queue records `delivered` at drain time,
/// before the child model has accepted a continuation.
fn render_noninteractive_agent_tree_late_steers(
    steers: &[crate::db::agent_tree_decisions::LateUserDecisionSteer],
) -> String {
    let mut out = String::from("[durable late user decision steer]\n");
    for (idx, steer) in steers.iter().enumerate() {
        out.push_str(&format!("{}. {}\n", idx + 1, steer.payload_json));
    }
    out.push_str("\nContinue this delegated task using the durable user decision above.");
    out
}

/// The session worker keeps the receiver for this acknowledgement outside its
/// main loop.  The noninteractive executor must therefore retain it until the
/// *whole* accepted continuation reaches a terminal model outcome; a single
/// provider round that returns `Continue` has only produced an intermediate
/// tool/result checkpoint.
type NoninteractiveLateSteerAck = (
    uuid::Uuid,
    uuid::Uuid,
    uuid::Uuid,
    String,
    tokio::sync::oneshot::Sender<crate::engine::driver::LateUserSteerContinuationOutcome>,
);

/// Finish accepted noninteractive steers only at the executor's actual
/// terminal `Done`/`Return` boundary.  Direct DB claims own both the durable
/// completion and delivery acknowledgement.  Mailbox-delivered claims notify
/// the session-worker receipt task after they complete; that task owns the
/// final delivery acknowledgement and schedules the next steer.
async fn complete_noninteractive_late_steer_continuation(
    session: &Session,
    claimed: &[crate::db::agent_tree_decisions::LateUserDecisionSteer],
    recovery_epoch: Option<uuid::Uuid>,
    externally_claimed: Vec<NoninteractiveLateSteerAck>,
) -> Result<()> {
    let now = crate::agent_tree::system_now_unix_ms();
    if !claimed.is_empty() {
        let epoch = recovery_epoch.context(
            "accepted noninteractive late steer has no recovery epoch at terminal completion",
        )?;
        for steer in claimed {
            anyhow::ensure!(
                session
                    .db
                    .complete_late_user_decision_steer_execution(
                        session.id,
                        steer.steer_id,
                        epoch,
                        now,
                    )
                    .await?,
                "noninteractive late steer completion lost its exact durable claim"
            );
            anyhow::ensure!(
                session
                    .db
                    .ack_late_user_decision_steer_delivery(session.id, steer.steer_id, epoch, now)
                    .await?,
                "completed noninteractive late steer acknowledgement lost its exact claim"
            );
        }
    }

    for (steer_id, _, recovery_epoch, _, respond_to) in externally_claimed {
        let outcome = match session
            .db
            .complete_late_user_decision_steer_execution(session.id, steer_id, recovery_epoch, now)
            .await
        {
            Ok(true) => crate::engine::driver::LateUserSteerContinuationOutcome::Completed,
            Ok(false) => crate::engine::driver::LateUserSteerContinuationOutcome::failed(
                "noninteractive late steer completion lost its exact durable claim",
            ),
            Err(error) => crate::engine::driver::LateUserSteerContinuationOutcome::failed(format!(
                "persisting noninteractive late steer completion failed: {error:#}"
            )),
        };
        let _ = respond_to.send(outcome);
    }
    Ok(())
}

/// A cancellation, provider failure, or parked tool is not a completion of an
/// accepted steer.  Accepted rows are intentionally no-redelivery durable
/// checkpoints, so this helper only reports the runtime outcome to the
/// session worker; it never releases or terminalizes those rows.
pub(in crate::engine::driver) fn retain_noninteractive_late_steer_checkpoint(
    claimed: &[crate::db::agent_tree_decisions::LateUserDecisionSteer],
    externally_claimed: Vec<NoninteractiveLateSteerAck>,
    outcome: crate::engine::driver::LateUserSteerContinuationOutcome,
) {
    for steer in claimed {
        tracing::warn!(
            steer_id = %steer.steer_id,
            agent_instance_id = %steer.agent_instance_id,
            ?outcome,
            "nonterminal noninteractive late steer outcome retained its accepted recovery checkpoint"
        );
    }
    for (_, _, _, _, respond_to) in externally_claimed {
        let _ = respond_to.send(outcome.clone());
    }
}

/// The final provider fence can lose to a new question or approval after an
/// executor has claimed a pending steer but before it has accepted it.  That
/// is deliberately not a terminal child failure: release only still-pending
/// direct claims, notify the session worker for mailbox claims, and let the
/// owner wait behind its newer continuation.  An already-accepted row is
/// intentionally untouched by the release CAS and remains its immutable
/// recovery unit.
async fn defer_noninteractive_late_steers_until_owner_is_runnable(
    session: &Session,
    claimed: &[crate::db::agent_tree_decisions::LateUserDecisionSteer],
    recovery_epoch: Option<uuid::Uuid>,
    externally_claimed: Vec<NoninteractiveLateSteerAck>,
) {
    if let Some(epoch) = recovery_epoch {
        let now = crate::agent_tree::system_now_unix_ms();
        for steer in claimed {
            match session
                .db
                .release_late_user_decision_steer_claim(session.id, steer.steer_id, epoch, now)
                .await
            {
                Ok(true) => tracing::debug!(
                    steer_id = %steer.steer_id,
                    agent_instance_id = %steer.agent_instance_id,
                    "released pending noninteractive late steer after owner parked before provider handoff"
                ),
                Ok(false) => tracing::debug!(
                    steer_id = %steer.steer_id,
                    agent_instance_id = %steer.agent_instance_id,
                    "noninteractive late steer was already accepted, terminalized, or claimed by newer recovery"
                ),
                Err(error) => tracing::warn!(
                    %error,
                    steer_id = %steer.steer_id,
                    agent_instance_id = %steer.agent_instance_id,
                    "failed to release deferred pending noninteractive late steer"
                ),
            }
        }
    }

    for (_, _, _, _, respond_to) in externally_claimed {
        let _ = respond_to.send(
            crate::engine::driver::LateUserSteerContinuationOutcome::interrupted(
                "noninteractive late steer is pending behind the owner's current continuation",
            ),
        );
    }
}

/// Rebuild the same provider-dispatch fence for an accepted steer whose
/// persisted `(history, next_prompt)` is already past the first provider
/// handoff.  The worker has independently validated the checkpoint before it
/// sends this request; this executor additionally requires that it belongs to
/// the exact snapshot it was reconstructed from.  In particular, the payload
/// is deliberately *not* rendered into a second prompt here.
fn recovered_noninteractive_late_steer_permit(
    expected_continuation_id: uuid::Uuid,
    agent_instance_id: Option<uuid::Uuid>,
    session: Arc<Session>,
    cancel: tokio_util::sync::CancellationToken,
    ack: &NoninteractiveLateSteerAck,
) -> std::result::Result<
    (
        uuid::Uuid,
        crate::engine::agent::AgentTreeSteerDispatchPermit,
    ),
    String,
> {
    let (steer_id, continuation_id, recovery_epoch, _, _) = ack;
    if *continuation_id != expected_continuation_id {
        return Err(
            "recovered noninteractive late steer continuation does not match its durable snapshot"
                .to_string(),
        );
    }
    let owner = agent_instance_id.ok_or_else(|| {
        "recovered noninteractive late steer reached an executor without a durable owner identity"
            .to_string()
    })?;
    Ok((
        *continuation_id,
        crate::engine::agent::AgentTreeSteerDispatchPermit::new(
            session,
            *steer_id,
            *continuation_id,
            owner,
            *recovery_epoch,
            cancel,
        ),
    ))
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

/// The durable continuation of a noninteractive executor.  Version one was a
/// ready-to-run `(history, next_prompt)` pair.  Version two additionally
/// records the one tool result that has not yet been injected because the
/// parent is waiting on its exact recursive executor set.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(in crate::engine::driver) struct NoninteractiveRecoverySnapshot {
    version: u8,
    history: Vec<Message>,
    #[serde(default)]
    next_prompt: Option<Message>,
    /// This marker proves that `history`/`next_prompt` already carry the
    /// first model handoff for an accepted late steer. It is private recovery
    /// state, never wire/UI content; a recovered executor uses it to restore
    /// the same permit without injecting the user payload again.
    #[serde(default)]
    pub(in crate::engine::driver) late_user_steer_continuation_id: Option<uuid::Uuid>,
    #[serde(default)]
    pending_recursive: Option<PendingRecursiveContinuation>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(in crate::engine::driver) struct PendingRecursiveContinuation {
    task_call_id: String,
    task_provider_item_id: Option<String>,
    task_function_call_id: Option<String>,
    repair_notes: Vec<String>,
    children: Vec<uuid::Uuid>,
    #[serde(default)]
    batch: bool,
    /// For a recursive batch, the exact topological launch order chosen while
    /// the parent checkpoint and all child descriptors were committed.  The
    /// authored `children` order remains the result-rendering order; this
    /// order is solely the durable dependency schedule used by recovery.
    batch_execution_order: Vec<uuid::Uuid>,
    /// Exact predecessor edges for a recursive batch.  A topological order is
    /// not an execution policy: retaining the edges lets recovery start every
    /// independent sibling immediately while each dependent waits only for
    /// its declared predecessors.  UUIDs, not display labels, make this
    /// resilient to identical child-agent names and preserve the authority
    /// boundary of the checkpoint that created the executors.
    batch_dependencies: std::collections::BTreeMap<uuid::Uuid, Vec<uuid::Uuid>>,
}

/// Produce a stable topological order without turning independent batch
/// entries into a barrier.  The parser normally validates this graph before a
/// `TurnOutcome` reaches the driver, but the recursive persistence boundary
/// validates it again because it is the authority that writes the restart
/// schedule.
fn recursive_batch_execution_order_labels(
    entries: &[crate::engine::agent::BatchTaskEntry],
) -> std::result::Result<Vec<String>, String> {
    crate::engine::agent::validate_batch_dependencies(entries)?;

    let mut completed = std::collections::BTreeSet::new();
    let mut pending = entries.iter().collect::<Vec<_>>();
    let mut order = Vec::with_capacity(entries.len());
    while !pending.is_empty() {
        let Some(index) = pending.iter().position(|entry| {
            entry
                .depends_on
                .iter()
                .all(|dependency| completed.contains(dependency))
        }) else {
            // `validate_batch_dependencies` has already ruled out cycles;
            // retaining a defensive error here keeps malformed in-memory
            // input from becoming a checkpoint that no recovery can obey.
            return Err("recursive batch has no dependency-ready child".to_string());
        };
        let entry = pending.remove(index);
        completed.insert(entry.label.clone());
        order.push(entry.label.clone());
    }
    Ok(order)
}

/// Validate and return the exact durable launch order for a recursive
/// checkpoint.  Both the pre-launch subtree collector and the runner call
/// this, so a malformed descriptor fails its reattach request rather than
/// publishing only the parent endpoint and then waiting forever for children
/// that can never be reconstructed.
fn recursive_recovery_execution_order(
    pending: &PendingRecursiveContinuation,
) -> Result<Vec<uuid::Uuid>> {
    anyhow::ensure!(
        !pending.children.is_empty(),
        "recursive parent checkpoint has no children"
    );
    let child_set = pending
        .children
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    anyhow::ensure!(
        child_set.len() == pending.children.len(),
        "recursive checkpoint contains duplicate child identities"
    );
    if pending.batch {
        anyhow::ensure!(
            pending.batch_execution_order.len() == pending.children.len(),
            "recursive batch checkpoint has no complete durable dependency schedule"
        );
        let scheduled = pending
            .batch_execution_order
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        anyhow::ensure!(
            scheduled == child_set,
            "recursive batch checkpoint dependency schedule does not name its exact child set"
        );
        anyhow::ensure!(
            pending.batch_dependencies.len() == pending.children.len()
                && pending
                    .children
                    .iter()
                    .all(|child| pending.batch_dependencies.contains_key(child)),
            "recursive batch checkpoint has no complete durable dependency edges"
        );
        let mut completed = std::collections::BTreeSet::new();
        for child in &pending.batch_execution_order {
            let dependencies = pending
                .batch_dependencies
                .get(child)
                .expect("validated recursive batch dependency entry");
            anyhow::ensure!(
                dependencies
                    .iter()
                    .all(|dependency| child_set.contains(dependency)),
                "recursive batch checkpoint dependency names a child outside its exact set"
            );
            anyhow::ensure!(
                dependencies
                    .iter()
                    .all(|dependency| completed.contains(dependency)),
                "recursive batch checkpoint schedule violates a declared predecessor edge"
            );
            completed.insert(*child);
        }
        Ok(pending.batch_execution_order.clone())
    } else {
        anyhow::ensure!(
            pending.children.len() == 1,
            "single recursive checkpoint must name exactly one child"
        );
        anyhow::ensure!(
            pending.batch_execution_order.is_empty(),
            "single recursive checkpoint unexpectedly carries a batch schedule"
        );
        anyhow::ensure!(
            pending.batch_dependencies.is_empty(),
            "single recursive checkpoint unexpectedly carries batch dependency edges"
        );
        Ok(pending.children.clone())
    }
}

fn ready_noninteractive_recovery_snapshot(
    history: Vec<Message>,
    next_prompt: Message,
) -> Result<String> {
    ready_noninteractive_recovery_snapshot_with_late_steer(history, next_prompt, None)
}

pub(in crate::engine::driver) fn ready_noninteractive_recovery_snapshot_with_late_steer(
    history: Vec<Message>,
    next_prompt: Message,
    late_user_steer_continuation_id: Option<uuid::Uuid>,
) -> Result<String> {
    serde_json::to_string(&NoninteractiveRecoverySnapshot {
        version: 2,
        history,
        next_prompt: Some(next_prompt),
        late_user_steer_continuation_id,
        pending_recursive: None,
    })
    .context("serializing ready noninteractive recovery snapshot")
}

fn validated_recursive_noninteractive_snapshot(
    raw: impl AsRef<str>,
) -> Result<crate::db::agent_tree_decisions::ValidatedRecursiveNoninteractiveSnapshot> {
    crate::db::agent_tree_decisions::ValidatedRecursiveNoninteractiveSnapshot::parse_and_canonicalize(raw)
        .context("validating recursive noninteractive continuation snapshot")
}

fn validated_recursive_noninteractive_launch(
    raw: impl AsRef<str>,
) -> Result<crate::db::agent_tree_decisions::ValidatedRecursiveNoninteractiveLaunch> {
    crate::db::agent_tree_decisions::ValidatedRecursiveNoninteractiveLaunch::parse_and_canonicalize(
        raw,
    )
    .context("validating recursive noninteractive launch descriptor")
}

fn waiting_recursive_recovery_snapshot(
    history: Vec<Message>,
    pending_recursive: PendingRecursiveContinuation,
    late_user_steer_continuation_id: Option<uuid::Uuid>,
) -> Result<String> {
    serde_json::to_string(&NoninteractiveRecoverySnapshot {
        version: 2,
        history,
        next_prompt: None,
        late_user_steer_continuation_id,
        pending_recursive: Some(pending_recursive),
    })
    .context("serializing waiting recursive recovery snapshot")
}

pub(in crate::engine::driver) fn parse_noninteractive_recovery_snapshot(
    raw: &str,
) -> Result<NoninteractiveRecoverySnapshot> {
    let snapshot: serde_json::Value =
        serde_json::from_str(raw).context("parsing noninteractive recovery snapshot")?;
    let version = snapshot
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .context("recovered noninteractive snapshot has no version")?;
    match version {
        1 => Ok(NoninteractiveRecoverySnapshot {
            version: 1,
            history: serde_json::from_value(
                snapshot
                    .get("history")
                    .cloned()
                    .context("recovered noninteractive snapshot has no history")?,
            )
            .context("decoding recovered noninteractive history")?,
            next_prompt: Some(
                serde_json::from_value(
                    snapshot
                        .get("next_prompt")
                        .cloned()
                        .context("recovered noninteractive snapshot has no next prompt")?,
                )
                .context("decoding recovered noninteractive next prompt")?,
            ),
            late_user_steer_continuation_id: None,
            pending_recursive: None,
        }),
        2 => serde_json::from_value(snapshot)
            .context("decoding version-two noninteractive recovery snapshot"),
        _ => anyhow::bail!("recovered noninteractive snapshot version is unsupported"),
    }
}

async fn collect_recursive_recovery_endpoint_ids(
    session: &Session,
    parent_agent_instance_id: uuid::Uuid,
    children: &[uuid::Uuid],
    collected: &mut std::collections::BTreeSet<uuid::Uuid>,
) -> Result<()> {
    for child_agent_instance_id in children {
        // A terminal recursive child has an immutable parent-visible outcome
        // rather than a runnable descriptor. It must not be included in the
        // exact mailbox set that reattach waits for, but it is still an
        // authority-bearing edge in the persisted checkpoint, so prove its
        // exact owner before treating its dependency gate as complete.
        if let Some(outcome) = session
            .db
            .recursive_noninteractive_outcome(session.id, *child_agent_instance_id)
            .await?
        {
            anyhow::ensure!(
                outcome.parent_agent_instance_id == parent_agent_instance_id,
                "recursive recovery checkpoint terminal child belongs to a different parent"
            );
            continue;
        }
        if !collected.insert(*child_agent_instance_id) {
            anyhow::bail!("recursive recovery checkpoint contains a child cycle");
        }
        let descriptor = session
            .db
            .recursive_noninteractive_recovery_descriptor(session.id, *child_agent_instance_id)
            .await?
            .with_context(|| format!("recursive recovery checkpoint references missing live child {child_agent_instance_id}"))?;
        let snapshot = parse_noninteractive_recovery_snapshot(descriptor.snapshot.as_json())?;
        if let Some(pending) = snapshot.pending_recursive {
            // Validate the whole checkpoint before advertising any endpoint
            // from this subtree. Otherwise a malformed batch schedule could
            // leave the worker waiting indefinitely for descendants that the
            // runner will correctly refuse to start.
            let _ = recursive_recovery_execution_order(&pending)?;
            Box::pin(collect_recursive_recovery_endpoint_ids(
                session,
                descriptor.agent_instance_id,
                &pending.children,
                collected,
            ))
            .await?;
        }
    }
    Ok(())
}

struct RecoveredRecursiveChildReport {
    agent_instance_id: uuid::Uuid,
    label: String,
    child_agent: String,
    report: String,
}

/// The immutable portion of a recursive executor.  Building this before an
/// endpoint is published is deliberately stronger than merely parsing its
/// JSON descriptor: grant, workspace, builtin, and continuation validation
/// all have to agree before recovery advertises a mailbox that a decision can
/// target.
struct PreparedRecoveredRecursiveExecutor {
    task_call_id: String,
    label: String,
    child_agent: String,
    child: Agent,
    child_cwd: std::path::PathBuf,
    snapshot: NoninteractiveRecoverySnapshot,
}

async fn prepare_recovered_recursive_noninteractive_executor(
    descriptor: &crate::db::agent_tree_decisions::RecursiveNoninteractiveRecoveryDescriptor,
    parent_agent: &Agent,
    parent_cwd: &std::path::Path,
    session: &Session,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    local_installations: &crate::agents::LocalInstallationResolver,
) -> Result<PreparedRecoveredRecursiveExecutor> {
    let launch: serde_json::Value = serde_json::from_str(descriptor.launch.as_json())
        .context("parsing recursive executor launch descriptor")?;
    anyhow::ensure!(
        launch.get("version").and_then(serde_json::Value::as_u64) == Some(2),
        "recursive executor launch descriptor version is unsupported"
    );
    let task_call_id = launch
        .get("task_call_id")
        .and_then(serde_json::Value::as_str)
        .context("recursive executor launch descriptor has no task call id")?
        .to_owned();
    let label = launch
        .get("label")
        .and_then(serde_json::Value::as_str)
        .context("recursive executor launch descriptor has no parent label")?
        .to_owned();
    let child_agent = launch
        .get("child_agent")
        .and_then(serde_json::Value::as_str)
        .context("recursive executor launch descriptor has no child agent")?
        .to_owned();
    let model =
        crate::engine::model_roles::DelegationModelSelector::from_value(launch.get("model"))
            .map_err(anyhow::Error::msg)?;
    let granted_tools = launch
        .get("granted_tools")
        .and_then(serde_json::Value::as_array)
        .context("recursive executor launch descriptor has no granted-tools snapshot")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("recursive executor granted tool is not a string")
        })
        .collect::<Result<Vec<_>>>()?;
    let raw_cwd = launch
        .get("cwd")
        .and_then(serde_json::Value::as_str)
        .context("recursive executor launch descriptor has no cwd")?;
    let child_cwd =
        resolve_recursive_vnext_child_cwd(Some(raw_cwd), parent_cwd, &session.project_root)
            .map_err(anyhow::Error::msg)?;
    let parent_grant = parent_agent
        .vnext_grant
        .as_ref()
        .context("recovered recursive executor parent has no vNext grant")?
        .clone();
    if let Some(error) =
        super::delegation_helpers::grant_rejection(super::delegation_helpers::GrantRejectionInput {
            parent_cwd,
            cwd: &child_cwd,
            config,
            parent_agent: &parent_agent.name,
            parent_vnext_grant: Some(&parent_grant),
            child_agent: &child_agent,
            grant: &granted_tools,
            assistant_db: &session.db,
            local_installations,
        })
        .await
    {
        anyhow::bail!("recovered recursive executor no longer passes its immutable grant: {error}");
    }
    let write_scope = resolve_write_scope(
        launch
            .get("write_scope")
            .and_then(serde_json::Value::as_str),
        &child_cwd,
        &session.project_root,
    )
    .map_err(anyhow::Error::msg)?;
    let child = crate::engine::builtin::load(
        &child_agent,
        &crate::engine::builtin::SpawnArgs {
            model: parent_agent.model.clone(),
            params: crate::engine::model::ModelParams {
                prompt_cache_key: None,
                prompt_cache_retention: None,
                ..parent_agent.params.clone()
            },
            env_overlay: parent_agent.env_overlay.clone(),
            cwd: child_cwd.clone(),
            config: config.clone(),
            session_short_id: session.short_id(),
            assistant_identity_prefix: parent_agent.assistant_identity_prefix.clone(),
            model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
            interactive: false,
            llm_mode: parent_agent.llm_mode,
            model_override: None,
            delegation_model: model,
            delegated: true,
            delegation_recursion: crate::engine::builtin::DelegationRecursionContext::default(),
            vnext_grant: None,
            vnext_host_policy: Some(Arc::new(parent_grant.host_policy.clone())),
            vnext_local_installation_resolver: local_installations.clone(),
            parent_vnext_grant: Some(parent_grant),
            swarm_depth: 0,
            swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
            granted_tools,
            lock_identity: None,
            write_scope,
            credential_store: session.provider_credential_store(&config.providers()).ok(),
        },
    )
    .context("loading recovered recursive noninteractive child")?;
    let snapshot = parse_noninteractive_recovery_snapshot(descriptor.snapshot.as_json())?;
    Ok(PreparedRecoveredRecursiveExecutor {
        task_call_id,
        label,
        child_agent,
        child,
        child_cwd,
        snapshot,
    })
}

/// Fully reconcile a recursive checkpoint before the parent is permitted to
/// expose any endpoint.  In particular, do not make a waiting sibling depend
/// on a mailbox that a malformed descriptor, revoked grant, invalid cwd, or
/// unavailable builtin can never create.
async fn preflight_pending_recursive_recovery(
    parent_agent_instance_id: uuid::Uuid,
    parent_agent: &Agent,
    parent_cwd: &std::path::Path,
    pending: &PendingRecursiveContinuation,
    session: &Session,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    local_installations: &crate::agents::LocalInstallationResolver,
) -> Result<()> {
    for child_agent_instance_id in recursive_recovery_execution_order(pending)? {
        // Completed recursive children deliberately have no live recovery
        // descriptor/mailbox. Their durable outcome is the restart-safe
        // dependency receipt; authorize it by the exact parent edge and let
        // live siblings/dependents continue through their normal preflight.
        if let Some(outcome) = session
            .db
            .recursive_noninteractive_outcome(session.id, child_agent_instance_id)
            .await?
        {
            anyhow::ensure!(
                outcome.parent_agent_instance_id == parent_agent_instance_id,
                "recursive parent checkpoint terminal child belongs to a different parent"
            );
            continue;
        }
        let descriptor = session
            .db
            .recursive_noninteractive_recovery_descriptor(session.id, child_agent_instance_id)
            .await?
            .with_context(|| format!("recursive parent checkpoint references missing live child {child_agent_instance_id}"))?;
        anyhow::ensure!(
            descriptor.parent_agent_instance_id == parent_agent_instance_id,
            "recursive parent checkpoint references a child owned by a different parent"
        );
        let prepared = prepare_recovered_recursive_noninteractive_executor(
            &descriptor,
            parent_agent,
            parent_cwd,
            session,
            config,
            local_installations,
        )
        .await?;
        if let Some(nested) = prepared.snapshot.pending_recursive.as_ref() {
            Box::pin(preflight_pending_recursive_recovery(
                descriptor.agent_instance_id,
                &prepared.child,
                &prepared.child_cwd,
                nested,
                session,
                config,
                local_installations,
            ))
            .await?;
        }
    }
    Ok(())
}

/// Reconstruct one recursive executor under the exact already-reconstructed
/// parent agent.  It deliberately does not consult the foreground driver's
/// stack: that stack represents a different executor after a restart and
/// would be an authority escalation for a nested vNext child.
async fn run_recovered_recursive_noninteractive_executor(
    descriptor: crate::db::agent_tree_decisions::RecursiveNoninteractiveRecoveryDescriptor,
    parent_agent: &Agent,
    parent_cwd: &std::path::Path,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    config: crate::daemon::session_worker::SessionConfigHandle,
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    max_turns: usize,
    local_installations: crate::agents::LocalInstallationResolver,
    tandem: Option<crate::engine::schedule::TandemSet>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    endpoint_collector: Option<std::sync::Arc<RecoveredNoninteractiveEndpointCollector>>,
    activation_gate: Option<crate::engine::driver::RecoveryActivationGate>,
    start_gate: Option<NoninteractiveStartGate>,
) -> Result<RecoveredRecursiveChildReport> {
    let PreparedRecoveredRecursiveExecutor {
        task_call_id,
        label,
        child_agent,
        child,
        child_cwd,
        snapshot,
    } = prepare_recovered_recursive_noninteractive_executor(
        &descriptor,
        parent_agent,
        parent_cwd,
        &session,
        &config,
        &local_installations,
    )
    .await?;
    let next_prompt = snapshot
        .next_prompt
        .unwrap_or_else(|| Message::user("[recovery: waiting for durable recursive child result]"));
    let outcome = run_noninteractive_resumable(
        child,
        next_prompt,
        snapshot.history,
        session,
        locks,
        redact,
        child_cwd,
        config,
        interrupts,
        cancel,
        approver,
        resource_scheduler,
        loop_guard_threshold,
        max_turns,
        local_installations,
        tandem,
        event_tx,
        Some(
            NoninteractiveSteerTarget::new(task_call_id, label.clone())
                .with_agent_instance_id(descriptor.agent_instance_id)
                .with_recovered_late_user_steer_continuation(
                    snapshot.late_user_steer_continuation_id,
                ),
        ),
        None,
        activation_gate,
        start_gate,
        endpoint_collector,
        snapshot.pending_recursive,
    )
    .await
    .map(|outcome| outcome.report)
    .unwrap_or_else(|error| format!("Error: {error}"));
    Ok(RecoveredRecursiveChildReport {
        agent_instance_id: descriptor.agent_instance_id,
        label,
        child_agent,
        report: outcome,
    })
}

/// Resolve the persisted children before the parent makes another model call.
/// The child UUID order is the authored result order, while the persisted
/// predecessor edges are the execution policy.  Recovery starts every child
/// immediately so each can publish its exact resolver endpoint; a child waits
/// only for the predecessors it explicitly declared.  This is important for
/// both correctness (independent children must remain independent after a
/// restart) and availability (decision replay must not wait for an unrelated
/// sibling to finish before its owner becomes addressable).
async fn recover_pending_recursive_continuation(
    parent_agent_instance_id: uuid::Uuid,
    parent_agent: &Agent,
    parent_cwd: &std::path::Path,
    history: Vec<Message>,
    pending: PendingRecursiveContinuation,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    config: crate::daemon::session_worker::SessionConfigHandle,
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    max_turns: usize,
    local_installations: crate::agents::LocalInstallationResolver,
    tandem: Option<crate::engine::schedule::TandemSet>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    endpoint_collector: Option<std::sync::Arc<RecoveredNoninteractiveEndpointCollector>>,
    activation_gate: Option<crate::engine::driver::RecoveryActivationGate>,
) -> Result<Message> {
    use futures::StreamExt as _;

    let child_positions = pending
        .children
        .iter()
        .copied()
        .enumerate()
        .map(|(position, child_agent_instance_id)| (child_agent_instance_id, position))
        .collect::<std::collections::HashMap<_, _>>();
    let execution_order = recursive_recovery_execution_order(&pending)?;
    let mut launches = Vec::with_capacity(pending.children.len());
    let mut recovered_terminal_reports = Vec::new();
    let mut recovered_terminal_ids = std::collections::BTreeSet::new();
    for child_agent_instance_id in execution_order {
        let idx = *child_positions
            .get(&child_agent_instance_id)
            .expect("validated recursive execution schedule names a child");
        if let Some(outcome) = session
            .db
            .recursive_noninteractive_outcome(session.id, child_agent_instance_id)
            .await?
        {
            anyhow::ensure!(
                outcome.parent_agent_instance_id == parent_agent_instance_id,
                "recursive outcome belongs to a different parent"
            );
            recovered_terminal_ids.insert(child_agent_instance_id);
            recovered_terminal_reports.push((
                idx,
                RecoveredRecursiveChildReport {
                    agent_instance_id: child_agent_instance_id,
                    label: outcome.label,
                    child_agent: outcome.child_agent,
                    report: outcome.report,
                },
            ));
            continue;
        }
        let descriptor = session
            .db
            .recursive_noninteractive_recovery_descriptor(session.id, child_agent_instance_id)
            .await?
            .with_context(|| format!("recursive parent checkpoint references missing live child {child_agent_instance_id}"))?;
        anyhow::ensure!(
            descriptor.parent_agent_instance_id == parent_agent_instance_id,
            "recursive parent checkpoint references a child owned by a different parent"
        );
        // Keep a presentation-only fallback before moving the immutable
        // descriptor into the reconstruction routine. It is used only when a
        // malformed launch cannot be rebuilt; it never influences authority
        // or recovery routing.
        let failure_launch =
            serde_json::from_str::<serde_json::Value>(descriptor.launch.as_json()).ok();
        let failure_label = failure_launch
            .as_ref()
            .and_then(|launch| launch.get("label"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("recovered-child-{}", idx + 1));
        let failure_child_agent = failure_launch
            .as_ref()
            .and_then(|launch| launch.get("child_agent"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        launches.push((
            idx,
            child_agent_instance_id,
            descriptor,
            failure_label,
            failure_child_agent,
        ));
    }
    let completion_senders = pending
        .children
        .iter()
        .copied()
        .map(|agent_instance_id| {
            let (sender, _receiver) = tokio::sync::watch::channel(false);
            (agent_instance_id, sender)
        })
        .collect::<std::collections::HashMap<_, _>>();
    // Previously committed children are already durable predecessors.  Their
    // dependents may begin immediately after recovery, while live siblings
    // retain their exact declared gates.
    for child_agent_instance_id in &recovered_terminal_ids {
        completion_senders
            .get(child_agent_instance_id)
            .expect("terminal recursive child has completion signal")
            .send_replace(true);
    }
    let parent_agent = parent_agent.clone();
    let parent_cwd = parent_cwd.to_path_buf();
    let execution_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(pending.children.len()));
    let mut runs = futures::stream::FuturesUnordered::new();
    for (idx, child_agent_instance_id, descriptor, failure_label, failure_child_agent) in launches {
        let dependencies = pending
            .batch_dependencies
            .get(&child_agent_instance_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|dependency| {
                completion_senders
                    .get(&dependency)
                    .expect("validated recursive batch dependency has a completion signal")
                    .subscribe()
            })
            .collect::<Vec<_>>();
        let completion_sender = completion_senders
            .get(&child_agent_instance_id)
            .expect("validated recursive child has a completion signal")
            .clone();
        let parent_agent = parent_agent.clone();
        let parent_cwd = parent_cwd.clone();
        let session = session.clone();
        let locks = locks.clone();
        let redact = redact.clone();
        let config = config.clone();
        let interrupts = interrupts.clone();
        let cancel = cancel.clone();
        let approver = approver.clone();
        let resource_scheduler = resource_scheduler.clone();
        let local_installations = local_installations.clone();
        let tandem = tandem.clone();
        let event_tx = event_tx.clone();
        let endpoint_collector = endpoint_collector.clone();
        let activation_gate = activation_gate.clone();
        let start_gate = NoninteractiveStartGate {
            dependencies,
            execution_slots: execution_slots.clone(),
        };
        runs.push(async move {
            let settlement_session = session.clone();
            let recovered = match Box::pin(run_recovered_recursive_noninteractive_executor(
                descriptor,
                &parent_agent,
                &parent_cwd,
                session,
                locks,
                redact,
                config,
                interrupts,
                cancel,
                approver,
                resource_scheduler,
                loop_guard_threshold,
                max_turns,
                local_installations,
                tandem,
                event_tx,
                endpoint_collector,
                activation_gate.clone(),
                Some(start_gate),
            ))
            .await
            {
                Ok(recovered) => recovered,
                Err(error)
                    if activation_gate
                        .as_ref()
                        .is_some_and(|gate| gate.is_aborted()) =>
                {
                    // The worker failed the all-or-nothing recovery claim.
                    // This is not a child execution failure: retain every
                    // exact durable checkpoint for the next epoch rather
                    // than settling a fabricated terminal report.
                    return Err(error);
                }
                Err(error) => RecoveredRecursiveChildReport {
                    // The descriptor was found and its durable parent ownership
                    // were verified before this executor was admitted. A
                    // malformed launch, revoked grant, or unavailable builtin
                    // is terminal for this child, never a retry loop.
                    agent_instance_id: child_agent_instance_id,
                    label: failure_label,
                    child_agent: failure_child_agent,
                    report: format!("Error: could not reconstruct recursive executor: {error:#}"),
                },
            };
            settlement_session
                .db
                .settle_recursive_noninteractive_child_outcome(
                    settlement_session.id,
                    parent_agent_instance_id,
                    child_agent_instance_id,
                    recovered.label.clone(),
                    recovered.child_agent.clone(),
                    recovered.report.clone(),
                    super::is_host_failure_sentinel(recovered.report.as_str()),
                    crate::agent_tree::system_now_unix_ms(),
                )
                .await?;
            completion_sender.send_replace(true);
            Ok::<_, anyhow::Error>((idx, recovered))
        });
    }
    let mut reports = recovered_terminal_reports;
    while let Some(report) = runs.next().await {
        reports.push(report?);
    }
    let terminal_children = reports
        .iter()
        .map(|(_, report)| {
            (
                report.agent_instance_id,
                super::is_host_failure_sentinel(report.report.as_str()),
            )
        })
        .collect::<Vec<_>>();
    let result = if pending.batch {
        render_recursive_vnext_batch_result(
            reports
                .iter()
                .map(|(idx, report)| {
                    (
                        *idx,
                        report.label.clone(),
                        report.child_agent.clone(),
                        report.report.clone(),
                    )
                })
                .collect(),
        )
    } else {
        anyhow::ensure!(
            reports.len() == 1,
            "single recursive checkpoint has multiple children"
        );
        reports.remove(0).1.report
    };
    let completed_next_prompt =
        crate::engine::message::synthetic_tool_result_message_with_provider_identity(
            pending.task_call_id,
            pending.task_provider_item_id,
            pending.task_function_call_id,
            "task",
            prepend_task_repair_notes(result, &pending.repair_notes),
        );
    let parent_snapshot =
        ready_noninteractive_recovery_snapshot(history, completed_next_prompt.clone())?;
    let parent_snapshot = validated_recursive_noninteractive_snapshot(&parent_snapshot)?;
    if let Err(error) = session
        .db
        .complete_recursive_noninteractive_children_and_checkpoint_parent(
            session.id,
            parent_agent_instance_id,
            parent_snapshot,
            terminal_children.clone(),
            crate::agent_tree::system_now_unix_ms(),
        )
        .await
    {
        // In particular, a child with a live Attention decision is forbidden
        // from terminalization. Wake the endpoint collector rather than
        // leaving recovery blocked forever on a descriptor that intentionally
        // did not create a runnable mailbox. The durable claim remains for a
        // later epoch, when the decision/grant can be reconciled safely.
        if let Some(collector) = endpoint_collector.as_ref() {
            let detail = format!("recursive terminal recovery failed: {error:#}");
            for (agent_instance_id, _) in &terminal_children {
                collector.report_unrecoverable(*agent_instance_id, detail.clone());
            }
        }
        return Err(error);
    }
    if let Some(collector) = endpoint_collector.as_ref() {
        for (agent_instance_id, _) in &terminal_children {
            collector.report_terminal(*agent_instance_id);
        }
    }
    Ok(completed_next_prompt)
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

/// Replay one already-terminal QuestionTool call inside the exact detached or
/// recursive executor that originally parked it.  This deliberately mirrors
/// the foreground driver's ordinary-call path rather than asking the model to
/// regenerate the pre-interrupt prompt: the persisted call id, arguments,
/// gate memo, response, and question occurrence remain the authority.
#[allow(clippy::too_many_arguments)]
async fn replay_parked_interrupt_in_noninteractive_executor(
    agent: &Agent,
    agent_instance_id: uuid::Uuid,
    history: &mut Vec<Message>,
    session: &Arc<Session>,
    locks: &Arc<crate::locks::LockManager>,
    redact: &Arc<RedactionTable>,
    cwd: &std::path::Path,
    config: &crate::daemon::session_worker::SessionConfigHandle,
    interrupts: &Arc<crate::engine::interrupt::InterruptHub>,
    approver: &Option<Arc<crate::approval::Approver>>,
    resource_scheduler: &Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    deferred_log: crate::engine::deferred::DeferredLog,
    tx: &mpsc::Sender<TurnEvent>,
    interrupt_id: uuid::Uuid,
    payload: crate::db::needs_attention::InterruptParkPayload,
    response: crate::daemon::proto::ResolveResponse,
    question: crate::engine::interrupt::PreResolvedInterruptQuestion,
) -> Result<()> {
    use rig::message::ToolFunction;

    // The exact AgentTree UUID is the continuation identity. The resume
    // anchor's agent name remains transcript/display provenance only, so a
    // renamed or same-named recursive executor cannot reject or steal this
    // replay on a string comparison.
    anyhow::ensure!(
        question.agent_instance_id == Some(agent_instance_id),
        "recovered QuestionTool identity does not match this noninteractive executor"
    );
    let active_tools = crate::engine::agent::turn_toolbox(agent, session, cwd, config).await;
    anyhow::ensure!(
        active_tools.get(&payload.tool).is_some(),
        "parked interrupt tool `{}` is not registered",
        payload.tool
    );
    super::delegation_helpers::ensure_or_restore_parked_tool_call(history, &payload)?;
    let ctx = crate::engine::tool::ToolCtx {
        agent_id: agent.name.clone(),
        agent_instance_id: Some(agent_instance_id),
        lock_identity: agent.name.clone(),
        write_scope: None,
        current_tool_call_id: None,
        llm_mode: agent.llm_mode,
        locks: locks.clone(),
        session: session.clone(),
        cwd: cwd.to_path_buf(),
        redact: redact.clone(),
        interrupts: interrupts.clone(),
        cancel: tokio_util::sync::CancellationToken::new(),
        shutdown_gate: agent.model.shutdown_gate(),
        approver: approver.clone(),
        image_generation_dispatch: None,
        deferred_log,
        root_agent_frame: false,
        skill_write_origin: payload.resume.call_origin,
        review_cage: None,
        context_usage: Some(crate::engine::tool::ContextUsageSnapshot::unavailable()),
        available_tools: Arc::new(
            active_tools
                .names()
                .into_iter()
                .map(str::to_string)
                .collect(),
        ),
        mcp_builtin_registry: active_tools.mcp_builtin_registry(),
        has_tree: agent.tools.get("code").is_some(),
        has_bash: agent.tools.get("bash").is_some(),
        events: Some(tx.clone()),
        lsp: None,
        resource_scheduler: resource_scheduler.clone(),
        env_overlay: agent.env_overlay.clone(),
        config: config.clone(),
    };
    let call = crate::engine::message::ToolCall {
        id: rig::message::ToolCallId::new_or_mint(payload.call_id.clone()),
        provider: payload
            .resume
            .provider_call_id
            .clone()
            .and_then(rig::message::ProviderCallId::new)
            .map(|provider| match payload.resume.provider_item_id.clone() {
                Some(item_id) => provider.with_item_id(item_id),
                None => provider,
            }),
        function: ToolFunction {
            name: payload.tool.clone(),
            arguments: payload.args.clone(),
        },
        signature: None,
        additional_params: None,
    };
    let config_snapshot = ctx.config.snapshot();
    let env = crate::engine::agent::tool_dispatch::DispatchEnv {
        agent,
        session,
        model: &agent.model,
        active_tools: &active_tools,
        ctx: &ctx,
        tx,
        hint_corrections: crate::engine::agent::hint_tool_call_corrections_enabled(session, config),
        loop_guard_threshold,
        cwd,
        hooks: config_snapshot.hooks(),
    };
    crate::engine::interrupt::with_pre_resolved_interrupt_question(
        interrupt_id,
        response,
        question,
        async {
            crate::engine::interrupt::with_interrupt_park_payload(payload.clone(), async {
                crate::engine::agent::tool_dispatch::execute_ordinary_call(
                    &env,
                    history,
                    &call,
                    &payload.tool,
                    crate::db::tool_calls::Recovery::Clean,
                    None,
                )
                .await
            })
            .await
        },
    )
    .await
}

/// Run a child agent's loop to completion, optionally **rehydrated** from a
/// prior transcript (`prior_history`). Returns the report + the full
/// transcript. [`run_noninteractive`] is the no-rehydrate wrapper used by the
/// `docs` pipeline.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_noninteractive_resumable(
    child: Agent,
    initial_prompt: Message,
    prior_history: Vec<Message>,
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
    // Model-comparison tandem (shadow) set (`model-comparison-tandem-
    // inference.md`). `Some(set)` when the session has model-comparison on, so
    // this leaf subagent's (`builder`/`explore`/`docs`) substantive turns are
    // shadowed too; `None`/empty disables it. Cheap clone per call.
    tandem: Option<crate::engine::schedule::TandemSet>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    steer_target: Option<NoninteractiveSteerTarget>,
    // Used only while reattaching a durable executor. The mailbox is handed
    // directly to the owning worker after its normal lifecycle registration
    // has been accepted, avoiding a polling race with the event forwarder.
    endpoint_ready: Option<
        tokio::sync::oneshot::Sender<
            std::result::Result<
                (
                    crate::engine::agent::AgentTreeEndpointGeneration,
                    tokio::sync::mpsc::Sender<crate::engine::agent::AgentTreeExecutorRequest>,
                ),
                String,
            >,
        >,
    >,
    activation_gate: Option<crate::engine::driver::RecoveryActivationGate>,
    start_gate: Option<NoninteractiveStartGate>,
    endpoint_collector: Option<std::sync::Arc<RecoveredNoninteractiveEndpointCollector>>,
    pending_recursive: Option<PendingRecursiveContinuation>,
) -> std::result::Result<NoninteractiveOutcome, NoninteractiveRunError> {
    use crate::engine::agent::turn_with_backup;

    let (child_tx, child_rx) = mpsc::channel::<TurnEvent>(64);
    // Recursive vNext structural tasks need the original sender for their
    // own nested forwarder.  The current child's forwarder owns only a clone.
    let forwarder =
        spawn_noninteractive_event_forwarder(child_rx, event_tx.clone(), steer_target.clone());

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
    let mut next_prompt = initial_prompt;
    let mut fallback_decision: Option<crate::engine::agent::BackupFallbackDecision> = None;
    let mut fallback_tried: Vec<crate::engine::agent::FailoverAttempt> = Vec::new();
    // The task row is the durable executor anchor on a restart.  A missing
    // mapping is intentionally left as `None` for non-delegation utility
    // callers; normal task creation binds it before an executor is spawned.
    let agent_instance_id = match &steer_target {
        Some(target) if target.agent_instance_id.is_some() => target.agent_instance_id,
        Some(target) => match session
            .db
            .task_delegation_child_agent(
                session.id,
                target.task_call_id.clone(),
                target.label.clone(),
            )
            .await
        {
            Ok(Some(agent)) => Some(agent.agent_instance_id),
            Ok(None) => {
                tracing::warn!(task_call_id = %target.task_call_id, label = %target.label, "noninteractive executor has no durable agent-tree child");
                None
            }
            Err(error) => {
                tracing::warn!(%error, task_call_id = %target.task_call_id, label = %target.label, "loading noninteractive task lifecycle child failed");
                None
            }
        },
        None => None,
    };
    let mut endpoint_ready = endpoint_ready;
    if let (Some(pending), Some(parent_agent_instance_id)) =
        (pending_recursive.as_ref(), agent_instance_id)
        && let Err(error) = Box::pin(preflight_pending_recursive_recovery(
            parent_agent_instance_id,
            agent.as_ref(),
            &cwd,
            pending,
            &session,
            &config,
            &local_installations,
        ))
        .await
    {
        // A recursive waiting checkpoint must be all-or-nothing from the
        // recovery worker's point of view.  If any descendant cannot be
        // reconstructed, fail this attempt before the parent or a sibling
        // exposes a resolver endpoint; otherwise a pending decision could be
        // routed into a partial tree that has no way to install the declared
        // endpoint set.
        let detail = format!("recursive recovery preflight failed: {error:#}");
        if let Some(endpoint_ready) = endpoint_ready.take() {
            let _ = endpoint_ready.send(Err(detail.clone()));
        }
        if let Some(collector) = endpoint_collector.as_ref() {
            collector.report_unrecoverable(parent_agent_instance_id, detail.clone());
        }
        drop(child_tx);
        let _ = forwarder.await;
        return Err(NoninteractiveRunError::new(
            anyhow::anyhow!(detail),
            history,
            fallback_decision,
            fallback_tried,
        ));
    }
    // Noninteractive children do not occupy the foreground driver stack, so
    // they publish their own exact mailbox. It is polled at the child's real
    // model-turn boundary below and completion is acknowledged through the
    // request's oneshot; merely enqueueing never counts as a warm receipt.
    let (agent_tree_resolver_tx, mut agent_tree_resolver_rx) = mpsc::channel(1);
    let agent_tree_endpoint_registration =
        match (agent_instance_id, event_tx.as_ref(), steer_target.as_ref()) {
            (Some(agent_instance_id), Some(event_tx), Some(target)) => {
                let endpoint_generation =
                    crate::engine::agent::next_agent_tree_endpoint_generation();
                if send_wrapped_noninteractive_event(
                    event_tx,
                    target,
                    TurnEvent::AgentTreeNoninteractiveEndpointAttached {
                        agent_instance_id,
                        endpoint_generation,
                        endpoint: agent_tree_resolver_tx.clone(),
                    },
                )
                .await
                {
                    // `Drop` cannot await a full bounded worker event channel.
                    // A private unbounded ingress plus this pump preserves the
                    // exact detach until worker backpressure clears.
                    let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();
                    let cleanup_event_tx = event_tx.clone();
                    let cleanup_target = target.clone();
                    tokio::spawn(async move {
                        while let Some(event) = cleanup_rx.recv().await {
                            if !send_wrapped_noninteractive_event(
                                &cleanup_event_tx,
                                &cleanup_target,
                                event,
                            )
                            .await
                            {
                                break;
                            }
                        }
                    });
                    Some(NoninteractiveAgentTreeEndpointRegistration {
                        cleanup_tx,
                        agent_instance_id,
                        endpoint_generation,
                    })
                } else {
                    None
                }
            }
            _ => None,
        };
    if let Some(endpoint_ready) = endpoint_ready {
        if agent_tree_endpoint_registration.is_none() {
            let _ = endpoint_ready.send(Err(
                "recovered noninteractive task could not register its lifecycle resolver endpoint"
                    .to_string(),
            ));
            drop(child_tx);
            let _ = forwarder.await;
            return Err(NoninteractiveRunError::new(
                anyhow::anyhow!(
                    "recovered noninteractive task could not register its lifecycle resolver endpoint"
                ),
                Vec::new(),
                None,
                Vec::new(),
            ));
        }
        let endpoint_generation = agent_tree_endpoint_registration
            .as_ref()
            .expect("checked live endpoint registration")
            .endpoint_generation;
        let _ = endpoint_ready.send(Ok((endpoint_generation, agent_tree_resolver_tx.clone())));
    }
    if let (Some(collector), Some(agent_instance_id), Some(registration)) = (
        endpoint_collector.as_ref(),
        agent_instance_id,
        agent_tree_endpoint_registration.as_ref(),
    ) {
        collector.register(
            agent_instance_id,
            registration.endpoint_generation,
            agent_tree_resolver_tx.clone(),
        );
    }
    // Reattachment snapshots intentionally preserve the input that was about
    // to enter `turn_with_backup`.  If that turn parked in QuestionTool, that
    // input is now a pre-interrupt prompt and must never be sent to the model
    // again.  The durable interrupt row is the source of truth across a
    // worker crash: publish the exact mailbox above, honor the declared start
    // gate, then wait there until a terminal decision redelivers the parked
    // call.  `Executing` is included because it is the persisted exactly-once
    // replay claim after a terminal decision has already won but before this
    // new executor consumed it.
    let mut parked_replay = match agent_instance_id {
        Some(agent_instance_id) => session
            .db
            .list_reconcilable_interrupts(session.id)
            .await
            .map_err(|error| {
                NoninteractiveRunError::new(
                    error
                        .context("loading durable parked continuation for noninteractive recovery"),
                    history.clone(),
                    fallback_decision.clone(),
                    fallback_tried.clone(),
                )
            })?
            .into_iter()
            .any(|row| {
                row.agent_instance_id == Some(agent_instance_id)
                    && row.parked.is_some()
                    && matches!(
                        row.state,
                        crate::db::needs_attention::InterruptState::Open
                            | crate::db::needs_attention::InterruptState::Parked
                            | crate::db::needs_attention::InterruptState::Executing
                    )
            }),
        None => false,
    };
    // Pre-activation recursive recovery is deliberately structural only: it
    // validates every immutable descriptor and starts every descendant far
    // enough to publish its UUID-owned mailbox, but every executor is still
    // stopped at `activation_gate` below.  Waiting for that gate before
    // constructing descendants deadlocks recovery: the worker needs their
    // endpoints to consume the complete claim set, while the descendants need
    // that consumption before they can start.  This applies even when this
    // parent has a parked QuestionTool continuation; no child can perform a
    // model/tool/effect action before the all-or-nothing acknowledgement.
    if let Some(pending) = pending_recursive {
        let Some(parent_agent_instance_id) = agent_instance_id else {
            drop(child_tx);
            let _ = forwarder.await;
            return Err(NoninteractiveRunError::new(
                anyhow::anyhow!("recovered recursive continuation has no durable parent identity"),
                history,
                fallback_decision,
                fallback_tried,
            ));
        };
        next_prompt = Box::pin(recover_pending_recursive_continuation(
            parent_agent_instance_id,
            agent.as_ref(),
            &cwd,
            history.clone(),
            pending,
            session.clone(),
            locks.clone(),
            redact.clone(),
            config.clone(),
            interrupts.clone(),
            cancel.clone(),
            approver.clone(),
            resource_scheduler.clone(),
            loop_guard_threshold,
            max_turns,
            local_installations.clone(),
            tandem.clone(),
            event_tx.clone(),
            endpoint_collector.clone(),
            activation_gate.clone(),
        ))
        .await
        .map_err(|error| {
            // A failure before every recursive descendant has registered is
            // not a missing-notification condition. The recovery caller must
            // retain its exact durable claim and retry/reconcile instead of
            // awaiting a mailbox that this parent can no longer create.
            if let Some(collector) = endpoint_collector.as_ref() {
                collector.report_unrecoverable(
                    parent_agent_instance_id,
                    format!("recursive continuation recovery failed: {error:#}"),
                );
            }
            NoninteractiveRunError::new(
                error,
                history.clone(),
                fallback_decision.clone(),
                fallback_tried.clone(),
            )
        })?;
    }
    // Endpoint publication is intentionally before activation: the recursive
    // preactivation phase above proves every exact executor is addressable,
    // then the session worker atomically consumes that entire claim set, and
    // only afterwards may any executor do model, tool, or host-effect work.
    // This closes both the partial-subtree and unclaimed-pre-crash-prompt
    // windows.
    if let Some(gate) = activation_gate.as_ref() {
        gate.wait().await.map_err(|error| {
            NoninteractiveRunError::new(error, history.clone(), None, Vec::new())
        })?;
    }
    // Publish the exact mailbox before waiting on declared predecessors. This
    // keeps recovery addressable without allowing a dependent to begin model
    // work ahead of its own dependency gate.
    let _recovery_execution_permit = match start_gate {
        Some(gate) => Some(gate.acquire(&cancel).await.map_err(|error| {
            NoninteractiveRunError::new(anyhow::anyhow!(error), history.clone(), None, Vec::new())
        })?),
        None => None,
    };
    // A noninteractive subagent's own deferred-log (`plan.md §3d`). Agents
    // that hold `defer_to_orchestrator` get their deferred items folded into
    // the leaf report they return up; agents without it keep this buffer empty.
    let deferred_log = crate::engine::deferred::DeferredLog::new();
    // Unlike an ordinary child turn, an accepted AgentTree steer spans every
    // model/tool continuation round until this executor reaches `Done` or
    // `Return`. Keep its immutable provider permit, first-handoff identity,
    // direct-claim receipt, and worker acknowledgement together across those
    // rounds. Dropping any of these after `Continue` used to falsely complete
    // a user steer as soon as its first tool call returned.
    let mut active_agent_tree_steer_permit = None;
    let mut active_agent_tree_steer_continuation_id = None;
    let mut active_agent_tree_steer_first_provider_handoff = false;
    // Only a fresh, still-pending steer replaces `next_prompt` with its
    // durable user body. If the final provider fence defers that first
    // handoff, restore the original continuation before waiting for the new
    // decision/replay. Recovered accepted checkpoints are already past this
    // substitution and must never pop their saved prompt.
    let mut active_agent_tree_steer_injected_prompt = false;
    let mut active_claimed_agent_tree_steers = Vec::new();
    let mut active_agent_tree_steer_epoch = None;
    let mut active_externally_claimed_agent_tree_steers: Vec<NoninteractiveLateSteerAck> =
        Vec::new();
    // A recovered snapshot carrying this marker is already past the first
    // provider handoff.  Do not let the ordinary loop send its saved prompt
    // until the worker has restored this exact continuation's permit.
    let recovered_agent_tree_steer_continuation_id = steer_target
        .as_ref()
        .and_then(|target| target.late_user_steer_continuation_id);
    'turns: for _ in 0..max_turns {
        if !parked_replay
            && active_agent_tree_steer_permit.is_none()
            && let Some(expected_continuation_id) = recovered_agent_tree_steer_continuation_id
        {
            // Endpoint publication and recovery activation have both happened
            // above.  The only valid next transition for this saved model/tool
            // checkpoint is the worker's exact resume request; running the
            // saved prompt first would execute the accepted user steer twice.
            let Some(request) = agent_tree_resolver_rx.recv().await else {
                return Err(NoninteractiveRunError::new(
                    anyhow::anyhow!(
                        "recovered noninteractive late steer executor mailbox closed before its exact continuation resumed"
                    ),
                    history,
                    fallback_decision,
                    fallback_tried,
                ));
            };
            match request {
                crate::engine::agent::AgentTreeExecutorRequest::ResolveDecision(request) => {
                    let response = agent
                        .model
                        .text_completion_with_live_context(
                            crate::engine::model::UtilityCallSite::AgentTreeDecision,
                            agent.params.clone(),
                            &agent.system,
                            &history,
                            &request.prompt,
                            &agent.name,
                            &cancel,
                        )
                        .await
                        .map_err(|error| {
                            format!("warm noninteractive resolver failed: {error:#}")
                        });
                    let _ = request.respond_to.send(response);
                    continue 'turns;
                }
                crate::engine::agent::AgentTreeExecutorRequest::ReplayParkedInterrupt {
                    respond_to,
                    ..
                } => {
                    // The durable interrupt scan above found no parked
                    // continuation, so this endpoint has no exact replay to
                    // consume. Preserve the late-steer checkpoint instead of
                    // letting an unrelated replay open its saved prompt.
                    let _ = respond_to.send(Err(
                        "noninteractive executor has no parked interrupt for this replay"
                            .to_string(),
                    ));
                    continue 'turns;
                }
                crate::engine::agent::AgentTreeExecutorRequest::DeliverLateUserDecisionSteer {
                    respond_to,
                    ..
                } => {
                    let _ = respond_to.send(
                        crate::engine::driver::LateUserSteerContinuationOutcome::interrupted(
                            "noninteractive executor is waiting for its recovered late steer continuation",
                        ),
                    );
                    continue 'turns;
                }
                crate::engine::agent::AgentTreeExecutorRequest::ResumeAcceptedLateUserDecisionSteer {
                    steer_id,
                    continuation_id,
                    recovery_epoch,
                    payload_json,
                    respond_to,
                    ..
                } => {
                    let ack = (
                        steer_id,
                        continuation_id,
                        recovery_epoch,
                        payload_json,
                        respond_to,
                    );
                    match recovered_noninteractive_late_steer_permit(
                        expected_continuation_id,
                        agent_instance_id,
                        session.clone(),
                        cancel.clone(),
                        &ack,
                    ) {
                        Ok((continuation_id, permit)) => {
                            active_agent_tree_steer_continuation_id = Some(continuation_id);
                            active_agent_tree_steer_first_provider_handoff = false;
                            active_agent_tree_steer_permit = Some(permit);
                            active_externally_claimed_agent_tree_steers = vec![ack];
                        }
                        Err(reason) => {
                            let _ = ack.4.send(
                                crate::engine::driver::LateUserSteerContinuationOutcome::failed(
                                    reason.clone(),
                                ),
                            );
                            return Err(NoninteractiveRunError::new(
                                anyhow::anyhow!(reason),
                                history,
                                fallback_decision,
                                fallback_tried,
                            ));
                        }
                    }
                }
            }
        }
        if parked_replay {
            // A replayed tool can itself park behind a second durable
            // QuestionTool seam. Keep this exact executor alive and consume
            // only its mailbox until that later terminal response arrives;
            // falling through to `turn_with_backup` here would regenerate the
            // pre-interrupt model prompt instead of resuming the parked call.
            let Some(request) = agent_tree_resolver_rx.recv().await else {
                retain_noninteractive_late_steer_checkpoint(
                    &active_claimed_agent_tree_steers,
                    std::mem::take(&mut active_externally_claimed_agent_tree_steers),
                    crate::engine::driver::LateUserSteerContinuationOutcome::interrupted(
                        "parked noninteractive executor mailbox closed before its continuation replay",
                    ),
                );
                return Err(NoninteractiveRunError::new(
                    anyhow::anyhow!("parked noninteractive executor mailbox closed"),
                    history,
                    fallback_decision,
                    fallback_tried,
                ));
            };
            match request {
                crate::engine::agent::AgentTreeExecutorRequest::ResolveDecision(request) => {
                    let response = agent
                        .model
                        .text_completion_with_live_context(
                            crate::engine::model::UtilityCallSite::AgentTreeDecision,
                            agent.params.clone(),
                            &agent.system,
                            &history,
                            &request.prompt,
                            &agent.name,
                            &cancel,
                        )
                        .await
                        .map_err(|error| format!("warm noninteractive resolver failed: {error:#}"));
                    let _ = request.respond_to.send(response);
                }
                crate::engine::agent::AgentTreeExecutorRequest::ReplayParkedInterrupt {
                    interrupt_id,
                    payload,
                    response,
                    question,
                    respond_to,
                } => {
                    let replay = replay_parked_interrupt_in_noninteractive_executor(
                        &agent,
                        agent_instance_id.expect("attached noninteractive executor has an agent UUID"),
                        &mut history,
                        &session,
                        &locks,
                        &redact,
                        &cwd,
                        &config,
                        &interrupts,
                        &approver,
                        &resource_scheduler,
                        loop_guard_threshold,
                        deferred_log.clone(),
                        &child_tx,
                        interrupt_id,
                        *payload,
                        response,
                        *question,
                    )
                    .await;
                    let replay = match replay {
                        Ok(()) => history
                            .pop()
                            .context("parked noninteractive replay produced no tool result")
                            .map(|tool_result| {
                                next_prompt = tool_result;
                                parked_replay = false;
                                crate::engine::driver::ParkedReplayOutcome::Completed
                            })
                            .map_err(|error| format!("{error:#}")),
                        Err(error) if crate::engine::interrupt::is_parked(&error) => {
                            Ok(crate::engine::driver::ParkedReplayOutcome::ParkedAgain)
                        }
                        Err(error) => Err(format!("{error:#}")),
                    };
                    let _ = respond_to.send(replay);
                }
                crate::engine::agent::AgentTreeExecutorRequest::DeliverLateUserDecisionSteer {
                    respond_to,
                    ..
                } => {
                    // A parked tool has no model-turn continuation in which a
                    // steer can be consumed. Leave its claim retryable rather
                    // than pretending queue receipt is execution.
                    let _ = respond_to.send(
                        crate::engine::driver::LateUserSteerContinuationOutcome::interrupted(
                            "noninteractive executor is parked behind an exact QuestionTool continuation",
                        ),
                    );
                }
                crate::engine::agent::AgentTreeExecutorRequest::ResumeAcceptedLateUserDecisionSteer {
                    steer_id,
                    continuation_id,
                    recovery_epoch,
                    payload_json,
                    respond_to,
                    ..
                } => {
                    let mut ack = Some((
                        steer_id,
                        continuation_id,
                        recovery_epoch,
                        payload_json,
                        respond_to,
                    ));
                    let outcome = match (
                        recovered_agent_tree_steer_continuation_id,
                        active_agent_tree_steer_permit.is_none(),
                    ) {
                        (Some(expected_continuation_id), true) => {
                            match recovered_noninteractive_late_steer_permit(
                                expected_continuation_id,
                                agent_instance_id,
                                session.clone(),
                                cancel.clone(),
                                ack.as_ref().expect("late-steer acknowledgement is still owned"),
                            ) {
                                Ok((continuation_id, permit)) => {
                                    active_agent_tree_steer_continuation_id = Some(continuation_id);
                                    active_agent_tree_steer_first_provider_handoff = false;
                                    active_agent_tree_steer_permit = Some(permit);
                                    active_externally_claimed_agent_tree_steers = vec![
                                        ack.take().expect(
                                            "successful late-steer recovery retains its acknowledgement",
                                        ),
                                    ];
                                    None
                                }
                                Err(reason) => Some(
                                    crate::engine::driver::LateUserSteerContinuationOutcome::failed(
                                        reason,
                                    ),
                                ),
                            }
                        }
                        _ => Some(
                            crate::engine::driver::LateUserSteerContinuationOutcome::interrupted(
                                "noninteractive executor is parked behind an exact QuestionTool continuation",
                            ),
                        ),
                    };
                    if let Some(outcome) = outcome {
                        let _ = ack
                            .take()
                            .expect("failed late-steer recovery retains its acknowledgement")
                            .4
                            .send(outcome);
                    }
                }
            }
            continue 'turns;
        }
        if let Some(target) = steer_target.as_ref() {
            match ready_noninteractive_recovery_snapshot_with_late_steer(
                history.clone(),
                next_prompt.clone(),
                active_agent_tree_steer_continuation_id
                    .or(recovered_agent_tree_steer_continuation_id),
            ) {
                Ok(snapshot_json) => {
                    let persisted = if target.agent_instance_id.is_some() {
                        session
                            .db
                            .persist_recursive_noninteractive_snapshot(
                                session.id,
                                agent_instance_id.expect("recursive target has an agent UUID"),
                                validated_recursive_noninteractive_snapshot(&snapshot_json)
                                    .map_err(|error| {
                                        NoninteractiveRunError::new(
                                            error,
                                            history.clone(),
                                            fallback_decision.clone(),
                                            fallback_tried.clone(),
                                        )
                                    })?,
                                crate::agent_tree::system_now_unix_ms(),
                            )
                            .await
                    } else {
                        session
                            .db
                            .persist_task_delegation_snapshot(
                                &target.task_call_id,
                                &target.label,
                                &snapshot_json,
                            )
                            .await
                    };
                    match persisted {
                        Ok(true) => {}
                        Ok(false) => {
                            retain_noninteractive_late_steer_checkpoint(
                                &active_claimed_agent_tree_steers,
                                std::mem::take(&mut active_externally_claimed_agent_tree_steers),
                                crate::engine::driver::LateUserSteerContinuationOutcome::failed(
                                    "noninteractive executor lost its durable recovery descriptor",
                                ),
                            );
                            return Err(NoninteractiveRunError::new(
                                anyhow::anyhow!(
                                    "noninteractive executor lost its durable recovery descriptor"
                                ),
                                history,
                                fallback_decision,
                                fallback_tried,
                            ));
                        }
                        Err(error) => {
                            retain_noninteractive_late_steer_checkpoint(
                                &active_claimed_agent_tree_steers,
                                std::mem::take(&mut active_externally_claimed_agent_tree_steers),
                                crate::engine::driver::LateUserSteerContinuationOutcome::failed(
                                    "persisting noninteractive task recovery snapshot failed",
                                ),
                            );
                            return Err(NoninteractiveRunError::new(
                                error.context("persisting noninteractive task recovery snapshot"),
                                history,
                                fallback_decision,
                                fallback_tried,
                            ));
                        }
                    }
                }
                Err(error) => {
                    retain_noninteractive_late_steer_checkpoint(
                        &active_claimed_agent_tree_steers,
                        std::mem::take(&mut active_externally_claimed_agent_tree_steers),
                        crate::engine::driver::LateUserSteerContinuationOutcome::failed(
                            "serializing noninteractive task recovery snapshot failed",
                        ),
                    );
                    return Err(NoninteractiveRunError::new(
                        error.into(),
                        history,
                        fallback_decision,
                        fallback_tried,
                    ));
                }
            }
        }
        // Drain only at an ordinary child turn boundary. A request accepted by
        // this mailbox is not complete until this exact child continuation has
        // consumed it, so a crashed/finished executor cannot yield a false
        // warm-parent, parked-replay, or late-steer receipt.
        let mut externally_claimed_agent_tree_steers: Vec<NoninteractiveLateSteerAck> = Vec::new();
        while let Ok(request) = agent_tree_resolver_rx.try_recv() {
            match request {
                crate::engine::agent::AgentTreeExecutorRequest::ResolveDecision(request) => {
                    let response = agent
                        .model
                        .text_completion_with_live_context(
                            crate::engine::model::UtilityCallSite::AgentTreeDecision,
                            agent.params.clone(),
                            &agent.system,
                            &history,
                            &request.prompt,
                            &agent.name,
                            &cancel,
                        )
                        .await
                        .map_err(|error| format!("warm noninteractive resolver failed: {error:#}"));
                    let _ = request.respond_to.send(response);
                }
                crate::engine::agent::AgentTreeExecutorRequest::ReplayParkedInterrupt {
                    interrupt_id,
                    payload,
                    response,
                    question,
                    respond_to,
                } => {
                    let replay = replay_parked_interrupt_in_noninteractive_executor(
                        &agent,
                        agent_instance_id.expect("attached noninteractive executor has an agent UUID"),
                        &mut history,
                        &session,
                        &locks,
                        &redact,
                        &cwd,
                        &config,
                        &interrupts,
                        &approver,
                        &resource_scheduler,
                        loop_guard_threshold,
                        deferred_log.clone(),
                        &child_tx,
                        interrupt_id,
                        *payload,
                        response,
                        *question,
                    )
                    .await;
                    let replay = match replay {
                        Ok(()) => history
                            .pop()
                            .context("parked noninteractive replay produced no tool result")
                            .map(|tool_result| {
                                next_prompt = tool_result;
                                crate::engine::driver::ParkedReplayOutcome::Completed
                            })
                            .map_err(|error| format!("{error:#}")),
                        Err(error) if crate::engine::interrupt::is_parked(&error) => {
                            Ok(crate::engine::driver::ParkedReplayOutcome::ParkedAgain)
                        }
                        Err(error) => Err(format!("{error:#}")),
                    };
                    let parked_again = matches!(
                        replay,
                        Ok(crate::engine::driver::ParkedReplayOutcome::ParkedAgain)
                    );
                    let _ = respond_to.send(replay);
                    if parked_again {
                        // The newly parked QuestionTool continuation is now
                        // durable. Do not re-run the old prompt; the next
                        // terminal delivery returns to this exact mailbox.
                        parked_replay = true;
                        break;
                    }
                }
                crate::engine::agent::AgentTreeExecutorRequest::DeliverLateUserDecisionSteer {
                    steer_id,
                    continuation_id,
                    recovery_epoch,
                    payload_json,
                    respond_to,
                } => externally_claimed_agent_tree_steers.push((
                    steer_id,
                    continuation_id,
                    recovery_epoch,
                    payload_json,
                    respond_to,
                )),
                crate::engine::agent::AgentTreeExecutorRequest::ResumeAcceptedLateUserDecisionSteer {
                    respond_to,
                    ..
                } => {
                    // A snapshot-backed resume is consumed by the recovery
                    // gate before this ordinary drain.  Never downgrade a
                    // late arrival into a fresh delivery, which would append
                    // the same durable user payload a second time.
                    let _ = respond_to.send(
                        crate::engine::driver::LateUserSteerContinuationOutcome::interrupted(
                            "noninteractive recovered late steer was not waiting on this executor checkpoint",
                        ),
                    );
                }
            }
        }
        if parked_replay {
            continue 'turns;
        }
        if let Some(target) = steer_target
            .as_ref()
            .filter(|target| target.agent_instance_id.is_none())
        {
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
        // AgentTree late steers are a separate, UUID-owned continuation
        // channel. Claim them only when this executor does not already own a
        // late-steer continuation. A `Continue` result leaves that
        // continuation live through further model/tool rounds, so folding a
        // second steer into it would lose both exact identities and
        // acknowledgements. The claim is intentionally still `pending` here:
        // the model-dispatch choke point commits acceptance only once this
        // exact owner is runnable and about to hand off to its provider.
        let mut claimed_agent_tree_steers = Vec::new();
        let mut agent_tree_steer_epoch = None;
        if active_agent_tree_steer_permit.is_none()
            && let Some(agent_instance_id) = agent_instance_id
        {
            let epoch = uuid::Uuid::now_v7();
            match session
                .db
                .claim_late_user_decision_steers(session.id, agent_instance_id, epoch)
                .await
            {
                Ok(steers) if !steers.is_empty() => {
                    let mut executable_steers = Vec::new();
                    for steer in steers {
                        // Completion commits before the outer delivery receipt.
                        // This child may therefore recover an acknowledgement
                        // without re-running the model turn that already
                        // consumed the durable user instruction.
                        if steer.completed_at_unix_ms.is_some() {
                            match session
                                .db
                                .ack_late_user_decision_steer_delivery(
                                    session.id,
                                    steer.steer_id,
                                    epoch,
                                    crate::agent_tree::system_now_unix_ms(),
                                )
                                .await
                            {
                                Ok(true) => continue,
                                Ok(false) => {
                                    return Err(NoninteractiveRunError::new(
                                        anyhow::anyhow!(
                                            "completed noninteractive late steer acknowledgement lost its exact claim"
                                        ),
                                        history,
                                        fallback_decision,
                                        fallback_tried,
                                    ));
                                }
                                Err(error) => {
                                    return Err(NoninteractiveRunError::new(
                                        error.context(
                                            "acknowledging completed noninteractive late steer",
                                        ),
                                        history,
                                        fallback_decision,
                                        fallback_tried,
                                    ));
                                }
                            }
                        }
                        executable_steers.push(steer);
                    }
                    if !executable_steers.is_empty() {
                        claimed_agent_tree_steers = executable_steers;
                        agent_tree_steer_epoch = Some(epoch);
                    }
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    %error,
                    %agent_instance_id,
                    "claiming noninteractive AgentTree late steers failed"
                ),
            }
        }
        if active_agent_tree_steer_permit.is_some()
            && !externally_claimed_agent_tree_steers.is_empty()
        {
            // The existing continuation remains its own recoverable unit.
            // Tell another live delivery attempt to retain/retry rather than
            // silently coalescing its external receipt into the first one.
            for (_, _, _, _, respond_to) in externally_claimed_agent_tree_steers {
                let _ = respond_to.send(
                    crate::engine::driver::LateUserSteerContinuationOutcome::interrupted(
                        "noninteractive executor is still completing an earlier accepted late steer",
                    ),
                );
            }
        } else if !claimed_agent_tree_steers.is_empty()
            || !externally_claimed_agent_tree_steers.is_empty()
        {
            // A steer continuation's id is stable across the mailbox/recovery
            // boundary.  It is the external journal identity for the *first*
            // provider handoff; the same permit stays installed for every
            // later tool/Continue round until the terminal receipt below.
            let (continuation_id, permit) = if let Some(steer) = claimed_agent_tree_steers.first() {
                let Some(recovery_epoch) = agent_tree_steer_epoch else {
                    return Err(NoninteractiveRunError::new(
                        anyhow::anyhow!("accepted noninteractive late steer has no recovery epoch"),
                        history,
                        fallback_decision,
                        fallback_tried,
                    ));
                };
                (
                    steer.continuation_id,
                    crate::engine::agent::AgentTreeSteerDispatchPermit::new(
                        session.clone(),
                        steer.steer_id,
                        steer.continuation_id,
                        steer.agent_instance_id,
                        recovery_epoch,
                        cancel.clone(),
                    ),
                )
            } else if let Some((steer_id, continuation_id, recovery_epoch, _, _)) =
                externally_claimed_agent_tree_steers.first()
            {
                let Some(owner) = agent_instance_id else {
                    return Err(NoninteractiveRunError::new(
                        anyhow::anyhow!(
                            "external AgentTree steer reached an executor without a durable owner identity"
                        ),
                        history,
                        fallback_decision,
                        fallback_tried,
                    ));
                };
                (
                    *continuation_id,
                    crate::engine::agent::AgentTreeSteerDispatchPermit::new(
                        session.clone(),
                        *steer_id,
                        *continuation_id,
                        owner,
                        *recovery_epoch,
                        cancel.clone(),
                    ),
                )
            } else {
                unreachable!("nonempty accepted steer set has no first identity")
            };
            let mut steer_sections = Vec::new();
            if !claimed_agent_tree_steers.is_empty() {
                steer_sections.push(render_noninteractive_agent_tree_late_steers(
                    &claimed_agent_tree_steers,
                ));
            }
            steer_sections.extend(externally_claimed_agent_tree_steers.iter().map(
                |(_, _, _, payload_json, _)| {
                    format!(
                        "[Durable late user decision steer for this continuation]\n{payload_json}"
                    )
                },
            ));
            history.push(next_prompt);
            next_prompt = Message::user(steer_sections.join("\n\n"));
            active_agent_tree_steer_continuation_id = Some(continuation_id);
            active_agent_tree_steer_first_provider_handoff = true;
            active_agent_tree_steer_injected_prompt = true;
            active_agent_tree_steer_permit = Some(permit);
            active_claimed_agent_tree_steers = claimed_agent_tree_steers;
            active_agent_tree_steer_epoch = agent_tree_steer_epoch;
            active_externally_claimed_agent_tree_steers = externally_claimed_agent_tree_steers;
        }
        let call_id = if active_agent_tree_steer_first_provider_handoff {
            active_agent_tree_steer_first_provider_handoff = false;
            active_agent_tree_steer_continuation_id
                .expect("active late steer always has its immutable continuation id")
        } else {
            uuid::Uuid::new_v4()
        };
        let agent_tree_steer_dispatch_permit = active_agent_tree_steer_permit.clone();
        let mut turn_metadata = BackupTurnMetadata::default();
        // Model-comparison tandem (shadow) set for this leaf subagent turn
        // (`builder`/`explore`/`docs`, `model-comparison-tandem-
        // inference.md`). Passed into `turn`, which dispatches the shadows from
        // the exact post-redaction body; a pure DB-only observer that never
        // enters the child's history or affects its loop. `None`/empty = off.
        let turn_future = crate::engine::agent::with_agent_instance_id(
            agent_instance_id,
            crate::engine::agent::with_agent_tree_steer_dispatch_permit(
                agent_tree_steer_dispatch_permit,
                turn_with_backup(
                    &agent,
                    backup_model.as_ref(),
                    &fallback_models,
                    &mut history,
                    next_prompt.clone(),
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
                ),
            ),
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
                // The first provider handoff succeeded, so the saved prompt
                // is now ordinary transcript history rather than a deferred
                // substitution we could roll back.
                active_agent_tree_steer_injected_prompt = false;
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
                if crate::engine::model::is_late_user_steer_deferred(&error) {
                    // No provider bytes were sent and the permit transaction
                    // left a pending row unaccepted. Restore the pre-steer
                    // prompt only for a new pending delivery, release that
                    // claim, and remain attached to the exact executor while
                    // the owner waits for its question/approval replay.
                    if active_agent_tree_steer_injected_prompt {
                        let Some(original_prompt) = history.pop() else {
                            return Err(NoninteractiveRunError::new(
                                anyhow::anyhow!(
                                    "deferred noninteractive late steer lost its original continuation prompt"
                                ),
                                history,
                                fallback_decision,
                                fallback_tried,
                            ));
                        };
                        next_prompt = original_prompt;
                        active_agent_tree_steer_injected_prompt = false;
                    }
                    defer_noninteractive_late_steers_until_owner_is_runnable(
                        &session,
                        &active_claimed_agent_tree_steers,
                        active_agent_tree_steer_epoch,
                        std::mem::take(&mut active_externally_claimed_agent_tree_steers),
                    )
                    .await;
                    active_claimed_agent_tree_steers.clear();
                    active_agent_tree_steer_epoch = None;
                    active_agent_tree_steer_permit = None;
                    active_agent_tree_steer_continuation_id = None;
                    // A nonterminal owner will eventually send this exact
                    // executor a replay after its current decision resolves.
                    // Terminal transitions reject pending rows atomically;
                    // their cancellation path owns executor shutdown.
                    parked_replay = true;
                    continue 'turns;
                }
                // Any other outcome reached (or got past) the provider
                // boundary. A later parked replay must not roll the original
                // prompt back if its accepted permit is subsequently revoked.
                active_agent_tree_steer_injected_prompt = false;
                if crate::engine::interrupt::is_parked(&error) {
                    // A parked QuestionTool is an intermediate continuation
                    // checkpoint, not a terminal steer outcome. Keep the
                    // accepted identity, provider permit, and worker receipt
                    // alive while this exact executor waits for the replay
                    // mailbox; the replay then feeds its tool result into the
                    // next turn under the same permit.
                    parked_replay = true;
                    continue 'turns;
                }
                let continuation_outcome = if crate::engine::model::is_cancelled(&error) {
                    crate::engine::driver::LateUserSteerContinuationOutcome::Cancelled
                } else {
                    crate::engine::driver::LateUserSteerContinuationOutcome::failed(format!(
                        "noninteractive late steer continuation failed: {error:#}"
                    ))
                };
                // Do not call `release_late_user_decision_steer_claim` here:
                // these rows are already in the irreversible `accepted`
                // state, and releasing is both ineffective and conceptually
                // wrong. Their immutable checkpoint is the recovery unit.
                retain_noninteractive_late_steer_checkpoint(
                    &active_claimed_agent_tree_steers,
                    std::mem::take(&mut active_externally_claimed_agent_tree_steers),
                    continuation_outcome,
                );
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
                if let Err(error) = complete_noninteractive_late_steer_continuation(
                    &session,
                    &active_claimed_agent_tree_steers,
                    active_agent_tree_steer_epoch,
                    std::mem::take(&mut active_externally_claimed_agent_tree_steers),
                )
                .await
                {
                    drop(child_tx);
                    let _ = forwarder.await;
                    return Err(NoninteractiveRunError::new(
                        error.context("persisting terminal noninteractive late steer completion"),
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
                if let Err(error) = complete_noninteractive_late_steer_continuation(
                    &session,
                    &active_claimed_agent_tree_steers,
                    active_agent_tree_steer_epoch,
                    std::mem::take(&mut active_externally_claimed_agent_tree_steers),
                )
                .await
                {
                    drop(child_tx);
                    let _ = forwarder.await;
                    return Err(NoninteractiveRunError::new(
                        error.context("persisting terminal noninteractive late steer completion"),
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
                let recovery_model = model.clone();
                let recovery_granted_tools = granted_tools.clone();
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
                    session_short_id: session.short_id(),
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
                let nested_steer_target = match (agent_instance_id, steer_target.as_ref()) {
                    (Some(parent_agent_instance_id), Some(parent_target)) => {
                        let child_agent_instance_id = uuid::Uuid::now_v7();
                        let recovery_anchor = uuid::Uuid::now_v7();
                        let waiting_snapshot = waiting_recursive_recovery_snapshot(
                            history.clone(),
                            PendingRecursiveContinuation {
                                task_call_id: task_call_id.clone(),
                                task_provider_item_id: task_provider_item_id.clone(),
                                task_function_call_id: task_function_call_id.clone(),
                                repair_notes: repair_notes.clone(),
                                children: vec![child_agent_instance_id],
                                batch: false,
                                batch_execution_order: Vec::new(),
                                batch_dependencies: std::collections::BTreeMap::new(),
                            },
                            active_agent_tree_steer_continuation_id
                                .or(recovered_agent_tree_steer_continuation_id),
                        );
                        match waiting_snapshot {
                            Ok(waiting_snapshot) => {
                                let launch_json = serde_json::to_string(&serde_json::json!({
                                    "version": 2,
                                    "task_call_id": &task_call_id,
                                    "label": &parent_target.label,
                                    "child_agent": &child_agent,
                                    "model": model_selector_json(&recovery_model),
                                    "granted_tools": &recovery_granted_tools,
                                    "cwd": child_cwd.to_string_lossy(),
                                    "write_scope": &write_scope,
                                }));
                                let snapshot_json = ready_noninteractive_recovery_snapshot(
                                    Vec::new(),
                                    Message::user(&prompt),
                                );
                                let descriptors = match (launch_json, snapshot_json) {
                                    (Ok(launch_json), Ok(snapshot_json)) => Some(
                                        validated_recursive_noninteractive_snapshot(
                                            &waiting_snapshot,
                                        )
                                        .and_then(
                                            |parent_snapshot| {
                                                validated_recursive_noninteractive_launch(
                                                    &launch_json,
                                                )
                                                .and_then(|launch| {
                                                    validated_recursive_noninteractive_snapshot(
                                                        &snapshot_json,
                                                    )
                                                    .map(|snapshot| {
                                                        (parent_snapshot, launch, snapshot)
                                                    })
                                                })
                                            },
                                        ),
                                    ),
                                    _ => None,
                                };
                                match descriptors {
                                Some(Ok((parent_snapshot, launch, snapshot))) => match session
                                    .db
                                    .create_recursive_noninteractive_executors_and_checkpoint_parent(
                                        session.id,
                                        parent_agent_instance_id,
                                        parent_snapshot,
                                        vec![crate::db::agent_tree_decisions::NewRecursiveNoninteractiveExecutor {
                                            agent_instance_id: child_agent_instance_id,
                                            recovery_anchor,
                                            launch,
                                            snapshot,
                                        }],
                                        crate::agent_tree::system_now_unix_ms(),
                                    )
                                    .await
                                {
                                    Ok(children) if children.len() == 1
                                        && children[0].agent_instance_id == child_agent_instance_id => {
                                        Some(parent_target.clone().with_agent_instance_id(child_agent_instance_id))
                                    }
                                    Ok(_) => {
                                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                            task_call_id,
                                            task_provider_item_id,
                                            task_function_call_id,
                                            "task",
                                            prepend_task_repair_notes(
                                                "Error: recursive executor checkpoint returned an unexpected child identity".to_string(),
                                                &repair_notes,
                                            ),
                                        );
                                        continue;
                                    }
                                    Err(error) => {
                                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                            task_call_id,
                                            task_provider_item_id,
                                            task_function_call_id,
                                            "task",
                                            prepend_task_repair_notes(
                                                format!("Error: could not persist recursive executor: {error:#}"),
                                                &repair_notes,
                                            ),
                                        );
                                        continue;
                                    }
                                },
                                Some(Err(error)) => {
                                    next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                        task_call_id,
                                        task_provider_item_id,
                                        task_function_call_id,
                                        "task",
                                        prepend_task_repair_notes(
                                            format!("Error: could not validate recursive executor descriptor: {error:#}"),
                                            &repair_notes,
                                        ),
                                    );
                                    continue;
                                }
                                None => {
                                    next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                        task_call_id,
                                        task_provider_item_id,
                                        task_function_call_id,
                                        "task",
                                        prepend_task_repair_notes(
                                            "Error: could not serialize recursive executor descriptor".to_string(),
                                            &repair_notes,
                                        ),
                                    );
                                    continue;
                                }
                            }
                            }
                            Err(error) => {
                                next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                    task_call_id,
                                    task_provider_item_id,
                                    task_function_call_id,
                                    "task",
                                    prepend_task_repair_notes(
                                        format!("Error: could not checkpoint recursive parent: {error:#}"),
                                        &repair_notes,
                                    ),
                                );
                                continue;
                            }
                        }
                    }
                    _ => None,
                };
                let nested_agent_instance_id = nested_steer_target
                    .as_ref()
                    .and_then(|target| target.agent_instance_id);
                let result = match crate::engine::builtin::load(&child_agent, &child_args) {
                    Ok(nested_child) => Box::pin(run_noninteractive_resumable(
                        nested_child,
                        Message::user(prompt),
                        Vec::new(),
                        session.clone(),
                        locks.clone(),
                        redact.clone(),
                        child_cwd,
                        config.clone(),
                        interrupts.clone(),
                        cancel.clone(),
                        approver.clone(),
                        resource_scheduler.clone(),
                        loop_guard_threshold,
                        max_turns,
                        local_installations.clone(),
                        tandem.clone(),
                        event_tx.clone(),
                        nested_steer_target,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ))
                    .await
                    .map(|outcome| outcome.report)
                    .unwrap_or_else(|error| format!("Error: {error}")),
                    Err(error) => format!("Error: {error:#}"),
                };
                let completed_next_prompt =
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id.clone(),
                        task_provider_item_id.clone(),
                        task_function_call_id.clone(),
                        "task",
                        prepend_task_repair_notes(result.clone(), &repair_notes),
                    );
                if let (Some(nested_agent_instance_id), Some(parent_agent_instance_id)) =
                    (nested_agent_instance_id, agent_instance_id)
                {
                    let parent_snapshot = ready_noninteractive_recovery_snapshot_with_late_steer(
                        history.clone(),
                        completed_next_prompt.clone(),
                        active_agent_tree_steer_continuation_id
                            .or(recovered_agent_tree_steer_continuation_id),
                    )
                    .map_err(|error| {
                        NoninteractiveRunError::new(
                            error,
                            history.clone(),
                            fallback_decision.clone(),
                            fallback_tried.clone(),
                        )
                    })?;
                    let parent_snapshot = validated_recursive_noninteractive_snapshot(
                        &parent_snapshot,
                    )
                    .map_err(|error| {
                        NoninteractiveRunError::new(
                            error,
                            history.clone(),
                            fallback_decision.clone(),
                            fallback_tried.clone(),
                        )
                    })?;
                    session
                        .db
                        .complete_recursive_noninteractive_children_and_checkpoint_parent(
                            session.id,
                            parent_agent_instance_id,
                            parent_snapshot,
                            vec![(
                                nested_agent_instance_id,
                                super::is_host_failure_sentinel(result.as_str()),
                            )],
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await
                        .map_err(|error| {
                            NoninteractiveRunError::new(
                                error.context("checkpointing recursive child completion"),
                                history.clone(),
                                fallback_decision.clone(),
                                fallback_tried.clone(),
                            )
                        })?;
                } else if let Some(nested_agent_instance_id) = nested_agent_instance_id {
                    terminalize_recursive_noninteractive_agent(
                        &session,
                        nested_agent_instance_id,
                        super::is_host_failure_sentinel(result.as_str()),
                    )
                    .await;
                }
                next_prompt = completed_next_prompt;
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
                let batch_execution_order = match recursive_batch_execution_order_labels(&entries) {
                    Ok(order) => order,
                    Err(error) => {
                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                            task_call_id,
                            task_provider_item_id,
                            task_function_call_id,
                            "task",
                            prepend_task_repair_notes(format!("Error: {error}"), &repair_notes),
                        );
                        continue;
                    }
                };
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
                        session_short_id: session.short_id(),
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

                // The parent first becomes durably waiting for the complete
                // batch, then every child node/descriptor is created in the
                // same transaction.  A restart can therefore recover the
                // batch result injection without treating siblings as orphaned
                // stand-alone work.
                let recursive_targets = match (agent_instance_id, steer_target.as_ref()) {
                    (Some(parent_agent_instance_id), Some(parent_target)) => {
                        let child_ids = prepared
                            .iter()
                            .map(|_| uuid::Uuid::now_v7())
                            .collect::<Vec<_>>();
                        let child_ids_by_label = prepared
                            .iter()
                            .zip(child_ids.iter().copied())
                            .map(|((_, entry, _, _), agent_instance_id)| {
                                (entry.label.as_str(), agent_instance_id)
                            })
                            .collect::<std::collections::HashMap<_, _>>();
                        let durable_batch_execution_order = batch_execution_order
                            .iter()
                            .map(|label| {
                                *child_ids_by_label.get(label.as_str()).expect(
                                    "validated recursive batch schedule names a prepared child",
                                )
                            })
                            .collect::<Vec<_>>();
                        let durable_batch_dependencies = prepared
                            .iter()
                            .zip(child_ids.iter().copied())
                            .map(|((_, entry, _, _), agent_instance_id)| {
                                let dependencies = entry
                                    .depends_on
                                    .iter()
                                    .map(|label| {
                                        child_ids_by_label
                                            .get(label.as_str())
                                            .copied()
                                            .expect("validated recursive batch dependency names a prepared child")
                                    })
                                    .collect::<Vec<_>>();
                                (agent_instance_id, dependencies)
                            })
                            .collect::<std::collections::BTreeMap<_, _>>();
                        let waiting_snapshot = waiting_recursive_recovery_snapshot(
                            history.clone(),
                            PendingRecursiveContinuation {
                                task_call_id: task_call_id.clone(),
                                task_provider_item_id: task_provider_item_id.clone(),
                                task_function_call_id: task_function_call_id.clone(),
                                repair_notes: repair_notes.clone(),
                                children: child_ids.clone(),
                                batch: true,
                                batch_execution_order: durable_batch_execution_order,
                                batch_dependencies: durable_batch_dependencies,
                            },
                            active_agent_tree_steer_continuation_id
                                .or(recovered_agent_tree_steer_continuation_id),
                        );
                        let children = prepared
                            .iter()
                            .zip(child_ids.iter().copied())
                            .map(|((_, entry, _, child_cwd), agent_instance_id)| {
                                Ok::<_, anyhow::Error>(
                                    crate::db::agent_tree_decisions::NewRecursiveNoninteractiveExecutor {
                                        agent_instance_id,
                                        recovery_anchor: uuid::Uuid::now_v7(),
                                        launch: validated_recursive_noninteractive_launch(serde_json::to_string(&serde_json::json!({
                                            "version": 2,
                                            "task_call_id": &task_call_id,
                                            "label": &parent_target.label,
                                            "depends_on": &entry.depends_on,
                                            "child_agent": &entry.child_agent,
                                            "model": model_selector_json(&entry.model),
                                            "granted_tools": &entry.granted_tools,
                                            "cwd": child_cwd.to_string_lossy(),
                                            "write_scope": &entry.write_scope,
                                        }))
                                        .context("serializing recursive batch child launch descriptor")?)?,
                                        snapshot: validated_recursive_noninteractive_snapshot(ready_noninteractive_recovery_snapshot(
                                            Vec::new(),
                                            Message::user(&entry.prompt),
                                        )?)?,
                                    },
                                )
                            })
                            .collect::<Result<Vec<_>>>();
                        let (waiting_snapshot, children) = match (waiting_snapshot, children) {
                            (Ok(waiting_snapshot), Ok(children)) => {
                                match validated_recursive_noninteractive_snapshot(&waiting_snapshot)
                                {
                                    Ok(waiting_snapshot) => (waiting_snapshot, children),
                                    Err(error) => {
                                        tracing::warn!(%error, "validating recursive batch parent checkpoint failed");
                                        next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                        task_call_id,
                                        task_provider_item_id,
                                        task_function_call_id,
                                        "task",
                                        prepend_task_repair_notes(
                                            "Error: could not validate recursive batch recovery checkpoint".to_string(),
                                            &repair_notes,
                                        ),
                                    );
                                        continue;
                                    }
                                }
                            }
                            (Err(error), _) | (_, Err(error)) => {
                                tracing::warn!(%error, "serializing recursive batch recovery checkpoint failed");
                                next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                    task_call_id,
                                    task_provider_item_id,
                                    task_function_call_id,
                                    "task",
                                    prepend_task_repair_notes(
                                        "Error: could not serialize recursive batch recovery checkpoint".to_string(),
                                        &repair_notes,
                                    ),
                                );
                                continue;
                            }
                        };
                        match session
                            .db
                            .create_recursive_noninteractive_executors_and_checkpoint_parent(
                                session.id,
                                parent_agent_instance_id,
                                waiting_snapshot,
                                children,
                                crate::agent_tree::system_now_unix_ms(),
                            )
                            .await
                        {
                            Ok(created)
                                if created.len() == child_ids.len()
                                    && created
                                        .iter()
                                        .zip(&child_ids)
                                        .all(|(child, id)| child.agent_instance_id == *id) =>
                            {
                                prepared
                                    .iter()
                                    .zip(child_ids)
                                    .map(|((idx, _, _, _), agent_instance_id)| {
                                        (
                                            *idx,
                                            parent_target
                                                .clone()
                                                .with_agent_instance_id(agent_instance_id),
                                        )
                                    })
                                    .collect::<std::collections::HashMap<_, _>>()
                            }
                            Ok(_) => {
                                next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                    task_call_id,
                                    task_provider_item_id,
                                    task_function_call_id,
                                    "task",
                                    prepend_task_repair_notes(
                                        "Error: recursive batch checkpoint returned unexpected child identities".to_string(),
                                        &repair_notes,
                                    ),
                                );
                                continue;
                            }
                            Err(error) => {
                                next_prompt = crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                                    task_call_id,
                                    task_provider_item_id,
                                    task_function_call_id,
                                    "task",
                                    prepend_task_repair_notes(
                                        format!("Error: could not checkpoint recursive batch: {error:#}"),
                                        &repair_notes,
                                    ),
                                );
                                continue;
                            }
                        }
                    }
                    _ => std::collections::HashMap::new(),
                };

                use futures::StreamExt as _;
                // Preserve the normal batch contract in the recursive path:
                // unrelated siblings begin immediately, while a dependent
                // starts only after each declared predecessor has reached a
                // terminal outcome.  These watches are an execution aid for
                // this live attempt; `batch_execution_order` above is the
                // durable equivalent used after a restart.
                let dependency_completion_senders = prepared
                    .iter()
                    .map(|(_, entry, _, _)| {
                        let (sender, _receiver) = tokio::sync::watch::channel(false);
                        (entry.label.clone(), sender)
                    })
                    .collect::<std::collections::HashMap<_, _>>();
                let mut runs = futures::stream::FuturesUnordered::new();
                for (idx, entry, child, child_cwd) in prepared {
                    let admission = vnext_admissions
                        .pop()
                        .expect("one vNext admission per prepared child");
                    let session = session.clone();
                    let locks = locks.clone();
                    let redact = redact.clone();
                    let config = config.clone();
                    let interrupts = interrupts.clone();
                    let cancel = cancel.clone();
                    let approver = approver.clone();
                    let resource_scheduler = resource_scheduler.clone();
                    let local_installations = local_installations.clone();
                    let tandem = tandem.clone();
                    let event_tx = event_tx.clone();
                    let nested_steer_target = recursive_targets.get(&idx).cloned();
                    let recursive_child_agent_instance_id = nested_steer_target
                        .as_ref()
                        .and_then(|target| target.agent_instance_id);
                    let recursive_parent_agent_instance_id = agent_instance_id;
                    let completion_sender = dependency_completion_senders
                        .get(&entry.label)
                        .expect("validated recursive batch child has completion signal")
                        .clone();
                    let dependency_receivers = entry
                        .depends_on
                        .iter()
                        .map(|label| {
                            dependency_completion_senders
                                .get(label)
                                .expect(
                                    "validated recursive batch dependency has completion signal",
                                )
                                .subscribe()
                        })
                        .collect::<Vec<_>>();
                    runs.push(async move {
                        // RAII releases each slot as soon as its child ends,
                        // including cancellation, errors, and panics.
                        let _admission = admission;
                        for mut dependency in dependency_receivers {
                            while !*dependency.borrow() {
                                tokio::select! {
                                    changed = dependency.changed() => {
                                        if changed.is_err() {
                                            let report = "Error: recursive batch dependency executor disappeared".to_string();
                                            if let (Some(child_agent_instance_id), Some(parent_agent_instance_id)) = (
                                                recursive_child_agent_instance_id,
                                                recursive_parent_agent_instance_id,
                                            ) {
                                                session
                                                    .db
                                                    .settle_recursive_noninteractive_child_outcome(
                                                        session.id,
                                                        parent_agent_instance_id,
                                                        child_agent_instance_id,
                                                        entry.label.clone(),
                                                        entry.child_agent.clone(),
                                                        report.clone(),
                                                        true,
                                                        crate::agent_tree::system_now_unix_ms(),
                                                    )
                                                    .await
                                                    .map_err(|error| format!(
                                                        "durably terminalizing recursive batch dependency failure failed: {error:#}"
                                                    ))?;
                                            }
                                            completion_sender.send_replace(true);
                                            return Ok::<_, String>((
                                                idx,
                                                entry.label,
                                                entry.child_agent,
                                                report,
                                            ));
                                        }
                                    }
                                    _ = cancel.cancelled() => {
                                        let report = "Error: recursive batch child cancelled before declared dependency completed".to_string();
                                        if let (Some(child_agent_instance_id), Some(parent_agent_instance_id)) = (
                                            recursive_child_agent_instance_id,
                                            recursive_parent_agent_instance_id,
                                        ) {
                                            session
                                                .db
                                                .settle_recursive_noninteractive_child_outcome(
                                                    session.id,
                                                    parent_agent_instance_id,
                                                    child_agent_instance_id,
                                                    entry.label.clone(),
                                                    entry.child_agent.clone(),
                                                    report.clone(),
                                                    true,
                                                    crate::agent_tree::system_now_unix_ms(),
                                                )
                                                .await
                                                .map_err(|error| format!(
                                                    "durably terminalizing cancelled recursive batch child failed: {error:#}"
                                                ))?;
                                        }
                                        completion_sender.send_replace(true);
                                        return Ok::<_, String>((
                                            idx,
                                            entry.label,
                                            entry.child_agent,
                                            report,
                                        ));
                                    }
                                }
                            }
                        }
                        let report = Box::pin(run_noninteractive_resumable(
                            child,
                            Message::user(entry.prompt),
                            Vec::new(),
                            session.clone(),
                            locks,
                            redact,
                            child_cwd,
                            config,
                            interrupts,
                            cancel,
                            approver,
                            resource_scheduler,
                            loop_guard_threshold,
                            max_turns,
                            local_installations,
                            tandem,
                            event_tx,
                            nested_steer_target,
                            None,
                            None,
                            None,
                            None,
                            None,
                        ))
                        .await
                        .map(|outcome| outcome.report)
                        .unwrap_or_else(|error| format!("Error: {error}"));
                        if let (Some(child_agent_instance_id), Some(parent_agent_instance_id)) = (
                            recursive_child_agent_instance_id,
                            recursive_parent_agent_instance_id,
                        ) {
                            session
                                .db
                                .settle_recursive_noninteractive_child_outcome(
                                    session.id,
                                    parent_agent_instance_id,
                                    child_agent_instance_id,
                                    entry.label.clone(),
                                    entry.child_agent.clone(),
                                    report.clone(),
                                    super::is_host_failure_sentinel(report.as_str()),
                                    crate::agent_tree::system_now_unix_ms(),
                                )
                                .await
                                .map_err(|error| format!(
                                    "durably terminalizing recursive batch predecessor failed: {error:#}"
                                ))?;
                        }
                        completion_sender.send_replace(true);
                        Ok((idx, entry.label, entry.child_agent, report))
                    });
                }
                let mut reports = Vec::new();
                while let Some(report) = runs.next().await {
                    reports.push(report.map_err(|error| {
                        NoninteractiveRunError::new(
                            anyhow::anyhow!(error),
                            history.clone(),
                            fallback_decision.clone(),
                            fallback_tried.clone(),
                        )
                    })?);
                }
                let terminal_children = reports
                    .iter()
                    .filter_map(|(idx, _, _, report)| {
                        recursive_targets
                            .get(idx)
                            .and_then(|target| target.agent_instance_id)
                            .map(|agent_instance_id| {
                                (
                                    agent_instance_id,
                                    super::is_host_failure_sentinel(report.as_str()),
                                )
                            })
                    })
                    .collect::<Vec<_>>();
                let result = render_recursive_vnext_batch_result(reports);
                let completed_next_prompt =
                    crate::engine::message::synthetic_tool_result_message_with_provider_identity(
                        task_call_id.clone(),
                        task_provider_item_id.clone(),
                        task_function_call_id.clone(),
                        "task",
                        prepend_task_repair_notes(result, &repair_notes),
                    );
                if let Some(parent_agent_instance_id) = agent_instance_id
                    && !terminal_children.is_empty()
                {
                    let parent_snapshot = ready_noninteractive_recovery_snapshot_with_late_steer(
                        history.clone(),
                        completed_next_prompt.clone(),
                        active_agent_tree_steer_continuation_id
                            .or(recovered_agent_tree_steer_continuation_id),
                    )
                    .map_err(|error| {
                        NoninteractiveRunError::new(
                            error,
                            history.clone(),
                            fallback_decision.clone(),
                            fallback_tried.clone(),
                        )
                    })?;
                    let parent_snapshot = validated_recursive_noninteractive_snapshot(
                        &parent_snapshot,
                    )
                    .map_err(|error| {
                        NoninteractiveRunError::new(
                            error,
                            history.clone(),
                            fallback_decision.clone(),
                            fallback_tried.clone(),
                        )
                    })?;
                    session
                        .db
                        .complete_recursive_noninteractive_children_and_checkpoint_parent(
                            session.id,
                            parent_agent_instance_id,
                            parent_snapshot,
                            terminal_children,
                            crate::agent_tree::system_now_unix_ms(),
                        )
                        .await
                        .map_err(|error| {
                            NoninteractiveRunError::new(
                                error.context("checkpointing recursive batch completion"),
                                history.clone(),
                                fallback_decision.clone(),
                                fallback_tried.clone(),
                            )
                        })?;
                }
                next_prompt = completed_next_prompt;
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
                retain_noninteractive_late_steer_checkpoint(
                    &active_claimed_agent_tree_steers,
                    std::mem::take(&mut active_externally_claimed_agent_tree_steers),
                    crate::engine::driver::LateUserSteerContinuationOutcome::failed(
                        "noninteractive agent produced an unsupported terminal continuation outcome",
                    ),
                );
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
    retain_noninteractive_late_steer_checkpoint(
        &active_claimed_agent_tree_steers,
        std::mem::take(&mut active_externally_claimed_agent_tree_steers),
        crate::engine::driver::LateUserSteerContinuationOutcome::failed(format!(
            "noninteractive agent `{}` exceeded {max_turns} turns",
            agent.name
        )),
    );
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

    #[tokio::test]
    async fn endpoint_drop_is_not_lost_when_the_worker_event_channel_is_full() {
        let owner = uuid::Uuid::new_v4();
        let (worker_tx, mut worker_rx) = mpsc::channel(1);
        let endpoint_generation = crate::engine::agent::next_agent_tree_endpoint_generation();
        // Fill the bounded worker lane before dropping the endpoint. A
        // try_send teardown would fail here and leave the registry stale.
        worker_tx
            .send(TurnEvent::AgentTreeExecutorEndpointAttached {
                agent_instance_id: owner,
                endpoint_generation,
            })
            .await
            .unwrap();
        let target = NoninteractiveSteerTarget::new("task-full", "child");
        let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();
        let pump_tx = worker_tx.clone();
        let pump_target = target.clone();
        let pump = tokio::spawn(async move {
            while let Some(event) = cleanup_rx.recv().await {
                if !send_wrapped_noninteractive_event(&pump_tx, &pump_target, event).await {
                    break;
                }
            }
        });
        let registration = NoninteractiveAgentTreeEndpointRegistration {
            cleanup_tx,
            agent_instance_id: owner,
            endpoint_generation,
        };
        drop(registration);

        assert!(matches!(
            worker_rx.recv().await,
            Some(TurnEvent::AgentTreeExecutorEndpointAttached { agent_instance_id, .. }) if agent_instance_id == owner
        ));
        let detached =
            tokio::time::timeout(std::time::Duration::from_millis(100), worker_rx.recv())
                .await
                .expect("private teardown pump must wait through worker backpressure");
        assert!(matches!(
            detached,
            Some(TurnEvent::NestedTurn { inner, .. })
                if matches!(inner.as_ref(), TurnEvent::AgentTreeExecutorEndpointDetached { agent_instance_id, .. } if *agent_instance_id == owner)
        ));
        drop(worker_tx);
        pump.await.unwrap();
    }

    #[tokio::test]
    async fn recursive_recovery_collector_reports_unreconstructable_child_instead_of_waiting() {
        let collector = RecoveredNoninteractiveEndpointCollector::new();
        let child = uuid::Uuid::new_v4();
        collector.report_unrecoverable(child, "immutable grant was revoked");
        let error = collector
            .wait_for(&std::collections::BTreeSet::from([child]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("grant was revoked"));
    }

    #[tokio::test]
    async fn recursive_recovery_collector_accepts_durable_terminal_outcome() {
        let collector = RecoveredNoninteractiveEndpointCollector::new();
        let live = uuid::Uuid::new_v4();
        let terminal = uuid::Uuid::new_v4();
        let (endpoint, _receiver) = tokio::sync::mpsc::channel(1);
        collector.register(
            live,
            crate::engine::agent::next_agent_tree_endpoint_generation(),
            endpoint,
        );
        collector.report_terminal(terminal);

        let endpoints = collector
            .wait_for(&std::collections::BTreeSet::from([live, terminal]))
            .await
            .unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].agent_instance_id, live);
    }

    #[tokio::test]
    async fn pending_recursive_restart_publishes_full_subtree_before_claim_activation() {
        let gate = crate::engine::driver::RecoveryActivationGate::new();
        let root = uuid::Uuid::new_v4();
        let nested = uuid::Uuid::new_v4();
        let collector = RecoveredNoninteractiveEndpointCollector::new();
        let (root_endpoint, _root_rx) = tokio::sync::mpsc::channel(1);
        let (nested_endpoint, _nested_rx) = tokio::sync::mpsc::channel(1);
        let nested_gate = gate.clone();
        let nested_wait = tokio::spawn(async move { nested_gate.wait().await });

        // A restart of a pending recursive continuation must let the worker
        // observe every live UUID-owned mailbox while the common activation
        // barrier is still closed.  If this publication waited for release,
        // the worker could never consume the full claim set that releases it.
        collector.register(
            root,
            crate::engine::agent::next_agent_tree_endpoint_generation(),
            root_endpoint,
        );
        collector.register(
            nested,
            crate::engine::agent::next_agent_tree_endpoint_generation(),
            nested_endpoint,
        );
        let endpoints = collector
            .wait_for(&std::collections::BTreeSet::from([root, nested]))
            .await
            .unwrap();
        assert_eq!(endpoints.len(), 2);
        assert!(
            !nested_wait.is_finished(),
            "no recursive model work may start before claim consumption"
        );

        gate.release();
        assert!(nested_wait.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn recovered_batch_waits_only_for_declared_dependencies() {
        let (base_done, dependent_watch) = tokio::sync::watch::channel(false);
        let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let cancel = tokio_util::sync::CancellationToken::new();
        let independent = NoninteractiveStartGate {
            dependencies: Vec::new(),
            execution_slots: slots.clone(),
        };
        let dependent = NoninteractiveStartGate {
            dependencies: vec![dependent_watch],
            execution_slots: slots,
        };

        // No edge points at `independent`, so it may start even while the
        // declared predecessor for the other child is unfinished.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                independent.acquire(&cancel),
            )
            .await
            .expect("independent child must not inherit an unrelated barrier")
            .is_ok()
        );
        let mut blocked = Box::pin(dependent.acquire(&cancel));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut blocked)
                .await
                .is_err()
        );
        base_done.send(true).unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), blocked)
                .await
                .expect("declared dependent should release after its predecessor")
                .is_ok()
        );
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
    fn recursive_recovery_keeps_dependency_edges_without_serializing_siblings() {
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let dependent = uuid::Uuid::new_v4();
        let pending = PendingRecursiveContinuation {
            task_call_id: "task".to_string(),
            task_provider_item_id: None,
            task_function_call_id: None,
            repair_notes: Vec::new(),
            children: vec![first, second, dependent],
            batch: true,
            batch_execution_order: vec![first, second, dependent],
            batch_dependencies: std::collections::BTreeMap::from([
                (first, Vec::new()),
                (second, Vec::new()),
                (dependent, vec![first]),
            ]),
        };
        assert_eq!(
            recursive_recovery_execution_order(&pending).unwrap(),
            vec![first, second, dependent],
            "the schedule remains a stable result order while runtime gates use the exact edge map"
        );
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
