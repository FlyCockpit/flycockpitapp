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
    pub(in crate::engine::driver) partial_progress: DelegationPartialProgress,
}

impl DelegationChildOutcome {
    pub(in crate::engine::driver) fn ok(report: impl Into<String>) -> Self {
        Self {
            report: report.into(),
            failed: false,
            partial_progress: DelegationPartialProgress::default(),
        }
    }

    pub(in crate::engine::driver) fn failed(report: impl Into<String>) -> Self {
        Self {
            report: report.into(),
            failed: true,
            partial_progress: DelegationPartialProgress::default(),
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
            partial_progress,
        }
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
    pub(in crate::engine::driver) granted_tools: Vec<String>,
    pub(in crate::engine::driver) prefill_seeds: Vec<crate::db::seed_tools::SeedTool>,
    pub(in crate::engine::driver) todo_ids: Vec<uuid::Uuid>,
    pub(in crate::engine::driver) skill_seed: Vec<String>,
    pub(in crate::engine::driver) child_recursion:
        crate::engine::builtin::DelegationRecursionContext,
    pub(in crate::engine::driver) repair_notes: Vec<String>,
    pub(in crate::engine::driver) task_call_id: String,
    pub(in crate::engine::driver) task_function_call_id: Option<String>,
}

pub(in crate::engine::driver) struct SingleNoninteractiveCompletion {
    pub(in crate::engine::driver) child_agent: String,
    pub(in crate::engine::driver) task_call_id: String,
    pub(in crate::engine::driver) task_function_call_id: Option<String>,
    pub(in crate::engine::driver) report: String,
    pub(in crate::engine::driver) failed: bool,
    pub(in crate::engine::driver) partial_progress: DelegationPartialProgress,
    pub(in crate::engine::driver) seeds: Vec<crate::db::seed_tools::SeedTool>,
    pub(in crate::engine::driver) new_handle: Option<String>,
    pub(in crate::engine::driver) snapshot: NoninteractiveDelegationSnapshot,
    pub(in crate::engine::driver) shrink: Option<PendingDelegationShrink>,
    pub(in crate::engine::driver) repair_notes: Vec<String>,
}

pub(in crate::engine::driver) struct BatchNoninteractiveTask {
    pub(in crate::engine::driver) entries: Vec<crate::engine::agent::BatchTaskEntry>,
    pub(in crate::engine::driver) child_cwds: Vec<ChildCwd>,
    pub(in crate::engine::driver) why: String,
    pub(in crate::engine::driver) repair_notes: Vec<String>,
    pub(in crate::engine::driver) task_call_id: String,
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
    pub(in crate::engine::driver) task_function_call_id: Option<String>,
    pub(in crate::engine::driver) children: Vec<BatchChildCompletion>,
    pub(in crate::engine::driver) repair_notes: Vec<String>,
}

pub(in crate::engine::driver) enum BackgroundNoninteractiveCompletion {
    Single {
        task_call_id: String,
        task_function_call_id: Option<String>,
        result: Box<Result<SingleNoninteractiveCompletion>>,
    },
    Batch {
        task_call_id: String,
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

impl Driver {
    pub(in crate::engine::driver) fn persist_delegation_payload(
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
            .with_context(|| {
                format!("persisting task delegation payload `{task_call_id}:{label}`")
            })?;
        let loaded = self
            .session
            .db
            .load_task_delegation_payload(task_call_id, label)
            .with_context(|| format!("loading task delegation payload `{task_call_id}:{label}`"))?;
        Ok(loaded.body)
    }

    pub(in crate::engine::driver) fn delegation_payload_delivery(
        &self,
        task_call_id: &str,
        label: &str,
        prompt: &str,
        retrieval_allowed: bool,
    ) -> Result<(Vec<Message>, String)> {
        let row = self
            .session
            .db
            .task_delegation_payload(task_call_id, label)?
            .with_context(|| format!("task delegation payload `{task_call_id}:{label}` missing"))?;
        if row.prompt_byte_len <= DELEGATION_PAYLOAD_DIRECT_LIMIT_BYTES {
            self.session
                .db
                .mark_task_delegation_payload_delivered(task_call_id, label)?;
            return Ok((Vec::new(), prompt.to_string()));
        }
        if !retrieval_allowed {
            bail!(DELEGATION_PAYLOAD_REFUSAL);
        }
        let history = delegation_payload_retrieval_history(&row, prompt);
        self.session
            .db
            .mark_task_delegation_payload_delivered(task_call_id, label)?;
        Ok((history, delegation_payload_reference_prompt(&row)))
    }

    pub(in crate::engine::driver) async fn run_single_noninteractive_task_backgroundable(
        &mut self,
        mut task: SingleNoninteractiveTask,
        input_rx: &crate::engine::message::UserSubmissionQueue,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Message> {
        let task_call_id = task.task_call_id.clone();
        let task_function_call_id = task.task_function_call_id.clone();
        let resolved_cwd_display = task.child_cwd.resolved_display();
        let task_args_json = serde_json::to_string(&serde_json::json!({
            "child_agent": &task.child_agent,
            "model": model_selector_json(&task.model),
            "why": &task.why,
            "resume_handle": &task.resume_handle,
            "requested_cwd": task.child_cwd.requested_json(),
            "resolved_cwd": &resolved_cwd_display,
            "todo_ids": &task.todo_ids,
            "skill_seed": &task.skill_seed,
        }))
        .ok();
        let parent_agent = self.stack.last().unwrap().agent.name.clone();
        if let Err(e) = self.session.db.upsert_task_delegation_job(
            self.session.id,
            &task_call_id,
            task_function_call_id.as_deref(),
            &parent_agent,
            task_args_json.as_deref(),
            &[crate::db::task_delegations::DelegationChildInit {
                label: "default",
                child_agent: &task.child_agent,
                model: model_selector_display(&task.model).as_deref(),
                output_dir: None,
                requested_cwd: task.child_cwd.requested_json(),
                resolved_cwd: Some(&resolved_cwd_display),
                todo_ids_json: None,
            }],
        ) {
            tracing::warn!(error = %e, task_call_id, "persist single task delegation job failed");
            return Ok(Message::tool_result_with_call_id(
                task_call_id,
                task_function_call_id,
                prepend_task_repair_notes(
                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                    &task.repair_notes,
                ),
            ));
        }
        match self.persist_delegation_payload(
            &task_call_id,
            task_function_call_id.as_deref(),
            &parent_agent,
            "default",
            &task.child_agent,
            &task.brief,
        ) {
            Ok(loaded) => task.brief = loaded,
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "persist single task delegation payload failed");
                return Ok(Message::tool_result_with_call_id(
                    task_call_id,
                    task_function_call_id,
                    prepend_task_repair_notes(
                        DELEGATION_PAYLOAD_REFUSAL.to_string(),
                        &task.repair_notes,
                    ),
                ));
            }
        }
        self.noninteractive_delegations.register_running(
            &task_call_id,
            "default",
            task.child_agent.clone(),
            NoninteractiveDelegationSnapshot::empty(),
        );
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let completion_task_call_id = task_call_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
        let handle = tokio::spawn(async move {
            let result = runner
                .execute_single_noninteractive_task(task, &tx_for_task, cancel)
                .await;
            let _ = complete_tx
                .send(BackgroundNoninteractiveCompletion::Single {
                    task_call_id: completion_task_call_id,
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
                {
                    tracing::warn!(error = %e, task_call_id, "background single task delegation failed");
                }
                let ack =
                    self.background_delegation_ack(&task_call_id, task_function_call_id.clone());
                if let Some(parent) = self.stack.last_mut() {
                    parent.history.push(ack);
                }
                let Some(prepared) = self.prepare_queued_user_submission(first, tx).await else {
                    return Ok(Message::user(""));
                };
                self.record_queued_user_fold(&prepared, tx).await;
                Ok(crate::engine::message::build_user_message(UserSubmission {
                    kind: UserSubmissionKind::User,
                    text: self.with_time_prelude(prepared.text),
                    images: prepared.images,
                    forced_skill: None,
                    origin_principal: None,
                    job_id: None,
                    preflight_cleaned: None,
                    queue_item_ids: Vec::new(),
                    queue_target: None,
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
            granted_tools,
            prefill_seeds,
            todo_ids,
            skill_seed,
            child_recursion,
            repair_notes,
            task_call_id,
            task_function_call_id,
        } = task;

        self.noninteractive_delegations.register_running(
            &task_call_id,
            "default",
            child_agent.clone(),
            NoninteractiveDelegationSnapshot::empty(),
        );

        if let Some(err) = grant_rejection(&child_cwd.resolved, &child_agent, &granted_tools) {
            return Ok(SingleNoninteractiveCompletion {
                child_agent,
                task_call_id,
                task_function_call_id,
                report: err,
                failed: true,
                partial_progress: DelegationPartialProgress::default(),
                seeds: Vec::new(),
                new_handle: None,
                snapshot: NoninteractiveDelegationSnapshot::empty(),
                shrink: None,
                repair_notes,
            });
        }

        let (delegation_payload_history, delivered_brief) = match self.delegation_payload_delivery(
            &task_call_id,
            "default",
            &brief,
            child_agent != "docs",
        ) {
            Ok(delivery) => delivery,
            Err(e) => {
                tracing::warn!(error = %e, task_call_id, "task delegation payload delivery failed");
                return Ok(SingleNoninteractiveCompletion {
                    child_agent,
                    task_call_id,
                    task_function_call_id,
                    report: DELEGATION_PAYLOAD_REFUSAL.to_string(),
                    failed: true,
                    partial_progress: DelegationPartialProgress::default(),
                    seeds: Vec::new(),
                    new_handle: None,
                    snapshot: NoninteractiveDelegationSnapshot::empty(),
                    shrink: None,
                    repair_notes,
                });
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
                trusted_only: self
                    .stack
                    .last()
                    .unwrap()
                    .agent
                    .model
                    .trusted_only_enabled(),
                model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                routing: routing.clone(),
            })
            .await;
        let task_identity = crate::engine::task_identity::TaskProviderIdentity::for_task_call(
            &task_call_id,
            task_function_call_id.as_deref(),
        );
        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::SubagentSpawned,
            Some(&self.stack.last().unwrap().agent.name),
            Some(&task_call_id),
            &serde_json::json!({
                "child_agent": child_agent.clone(),
                "task_call_id": task_call_id,
                "provider_call_id": task_identity.provider_call_id,
                "provider_call_id_source": task_identity.provider_call_id_source,
                "provider_identity": task_identity.event_identity_json(&task_call_id),
                "label": "default",
                "noninteractive": true,
                "prompt": delivered_brief.clone(),
                "why": why.clone(),
                "model": model_selector_json(&model),
                "trusted_only": self.stack.last().unwrap().agent.model.trusted_only_enabled(),
                "model_trusted": self.stack.last().unwrap().agent.model.is_trusted(),
                "routing": routing,
                "remaining_depth": remaining_depth,
                "resume_handle": resume_handle.clone(),
                "requested_cwd": child_cwd.requested_json(),
                "resolved_cwd": child_cwd.resolved_display(),
                "grant_tools": granted_tools.clone(),
                "seed": prefill_seeds.clone(),
                "skill_seed": skill_seed.clone(),
                "todo_ids": todo_ids.clone(),
            }),
        ) {
            tracing::warn!(error = %e, "record single subagent_spawned event failed");
        }

        let parent_full = self
            .stack
            .last()
            .expect("stack never empty")
            .history
            .clone();
        let (tracker, shrink_handle) = self.begin_delegation_shrink(parent_full);

        let llm_mode = self.stack[0].agent.llm_mode;
        let followup_enabled = crate::engine::tool::Capability::FollowupSeed.enabled(llm_mode);
        let skill_block = self.seed_skills_block(&skill_seed, &child_agent);
        let composed_brief = compose_subagent_brief(&delivered_brief, &why);
        let composed_brief = if skill_block.is_empty() {
            composed_brief
        } else {
            format!("{skill_block}{composed_brief}")
        };
        let mut seeds: Vec<crate::db::seed_tools::SeedTool> = Vec::new();
        let mut new_handle: Option<String> = None;
        let mut snapshot = NoninteractiveDelegationSnapshot::empty();
        let composed_brief = self.assign_todos_to_task(
            composed_brief,
            &todo_ids,
            &task_call_id,
            "default",
            &child_agent,
        );

        let outcome = if child_agent == "docs" {
            if resume_handle.is_some() {
                DelegationChildOutcome::failed(stale_handle_error(&child_agent))
            } else {
                match crate::engine::docs_pipeline::run(
                    &delivered_brief,
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
                    Ok(text) => DelegationChildOutcome::ok(text),
                    Err(e) => DelegationChildOutcome::failed(format!("Error: {e:#}")),
                }
            }
        } else {
            let rehydrated = match &resume_handle {
                None => Ok(Vec::new()),
                Some(handle) => self.rehydrate_handle(
                    handle,
                    &child_agent,
                    Some(&child_cwd.resolved),
                    followup_enabled,
                ),
            };
            match rehydrated {
                Err(msg) => DelegationChildOutcome::failed(msg),
                Ok(prior_history) => {
                    let child = match crate::engine::builtin::load(
                        &child_agent,
                        &self.spawn_args_delegated_in_cwd(
                            &child_cwd.resolved,
                            false,
                            granted_tools.clone(),
                            model.clone(),
                            child_recursion.clone(),
                        ),
                    ) {
                        Ok(child) => child,
                        Err(e) => {
                            return Ok(SingleNoninteractiveCompletion {
                                child_agent,
                                task_call_id,
                                task_function_call_id,
                                report: format!("Error: {e:#}"),
                                failed: true,
                                partial_progress: DelegationPartialProgress::default(),
                                seeds: Vec::new(),
                                new_handle: None,
                                snapshot: NoninteractiveDelegationSnapshot::empty(),
                                shrink: Some(PendingDelegationShrink {
                                    tracker,
                                    handle: shrink_handle,
                                }),
                                repair_notes,
                            });
                        }
                    };
                    let read_only = crate::engine::builtin::is_read_only_noninteractive(&child);
                    let write_capable = crate::engine::builtin::is_write_capable(&child);
                    if resume_handle.is_some() && write_capable {
                        match self.locks.resume_agent(&child_agent, self.session.id) {
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
                        if let Err(e) = self.session.record_event(
                            crate::db::session_log::SessionEventKind::SubagentSpawned,
                            Some(&child_agent),
                            Some(&task_call_id),
                            &serde_json::json!({
                                "followup_resume": true,
                                "reuse_decision": format!("{reuse:?}"),
                                "write_capable": write_capable,
                            }),
                        ) {
                            tracing::warn!(error = %e, "record followup reuse event failed");
                        }
                    }
                    let (seed_prefix, seeds_truncated) = self
                        .prefill_child_seeds(&prefill_seeds, &child, &child_cwd.resolved, None)
                        .await;
                    let mut prior_history = prior_history;
                    let mut delivery_history = delegation_payload_history.clone();
                    let mut seed_prefix = seed_prefix;
                    if !delivery_history.is_empty() || !seed_prefix.is_empty() {
                        delivery_history.append(&mut seed_prefix);
                        delivery_history.append(&mut prior_history);
                        prior_history = delivery_history;
                    }
                    let composed_brief = if seeds_truncated {
                        format!("{composed_brief}{SEED_PREFILL_TRUNCATION_NOTE}")
                    } else {
                        composed_brief.clone()
                    };
                    let collector = crate::engine::seed_collector::SeedCollector::new();
                    match run_noninteractive_resumable(
                        child,
                        composed_brief,
                        prior_history,
                        collector.clone(),
                        self.session.clone(),
                        self.locks.clone(),
                        self.redact.clone(),
                        child_cwd.resolved.clone(),
                        self.interrupts.clone(),
                        cancel,
                        self.approver.clone(),
                        self.resource_scheduler.clone(),
                        self.loop_guard_threshold,
                        EXPLORE_MAX_TURNS,
                        Some(self.tandem_set.clone()),
                        Some(tx.clone()),
                        Some(NoninteractiveSteerTarget::new(
                            task_call_id.clone(),
                            "default",
                        )),
                    )
                    .await
                    {
                        Err(e) => {
                            let (message, history) = e.into_parts();
                            let partial_progress = partial_progress_from_history(&history);
                            snapshot = NoninteractiveDelegationSnapshot::from_history(history);
                            DelegationChildOutcome::failed_with_progress(
                                format!("Error: {message}"),
                                partial_progress,
                            )
                        }
                        Ok(outcome) => {
                            snapshot = NoninteractiveDelegationSnapshot::from_history(
                                outcome.history.clone(),
                            );
                            if followup_enabled
                                && crate::engine::builtin::is_followup_eligible(&child_agent)
                            {
                                new_handle = self.persist_subagent_handle(
                                    &child_agent,
                                    &outcome.history,
                                    Some(&child_cwd.resolved),
                                    resume_handle.as_deref(),
                                );
                                if read_only {
                                    seeds = collector.drain();
                                }
                                if write_capable
                                    && let Err(e) =
                                        self.locks.suspend_agent(&child_agent, self.session.id)
                                {
                                    tracing::warn!(error = ?e, agent = %child_agent, "followup suspend_agent at finish failed");
                                }
                            }
                            DelegationChildOutcome::ok(outcome.report)
                        }
                    }
                }
            }
        };

        Ok(SingleNoninteractiveCompletion {
            child_agent,
            task_call_id,
            task_function_call_id,
            report: outcome.report,
            failed: outcome.failed,
            partial_progress: outcome.partial_progress,
            seeds,
            new_handle,
            snapshot,
            shrink: Some(PendingDelegationShrink {
                tracker,
                handle: shrink_handle,
            }),
            repair_notes,
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
            task_function_call_id,
            report,
            failed,
            partial_progress,
            seeds,
            new_handle,
            snapshot,
            shrink,
            repair_notes,
        } = completion;

        let emit_report_event = shrink.is_some();
        if !emit_report_event {
            let report = prepend_task_repair_notes(report, &repair_notes);
            let report = self
                .maybe_scan_task_report(&child_agent, report, tx)
                .await?;
            let result = Message::tool_result_with_call_id(
                task_call_id.clone(),
                task_function_call_id,
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
            if let Err(e) = self.session.db.complete_task_delegation_child(
                &task_call_id,
                "default",
                &report,
                failed,
                None,
            ) {
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

        let seeds_truncated = if seeds.is_empty() {
            false
        } else {
            self.inject_seeds(&seeds, &task_call_id, tx).await
        };

        let mut report = report;
        if seeds_truncated {
            report.push_str(
                "\n\n[note: some seeded results were omitted to stay within the report budget]",
            );
        }
        let report =
            self.reconcile_todo_delta(&task_call_id, "default", &child_agent, &report, failed);
        let report = match &new_handle {
            Some(handle) => format!("{report}{}", handle_footer(handle)),
            None => report,
        };
        let report = prepend_task_repair_notes(report, &repair_notes);
        let report = self
            .maybe_scan_task_report(&child_agent, report, tx)
            .await?;

        if let Err(e) = self.session.record_event(
            crate::db::session_log::SessionEventKind::SubagentReport,
            Some(&child_agent),
            Some(&task_call_id),
            &with_model_routing_metadata(
                subagent_report_event_data(
                    &child_agent,
                    Some(&task_call_id),
                    task_function_call_id.as_deref(),
                    "default",
                    &report,
                    Some(&partial_progress),
                ),
                &self.stack.last().unwrap().agent.model,
            ),
        ) {
            tracing::warn!(error = %e, "record subagent_report event failed");
        }
        let _ = tx
            .send(TurnEvent::SubagentReport {
                agent: child_agent.clone(),
                task_call_id: task_call_id.clone(),
                label: "default".to_string(),
                report: report.clone(),
                trusted_only: self
                    .stack
                    .last()
                    .unwrap()
                    .agent
                    .model
                    .trusted_only_enabled(),
                model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                routing: self
                    .stack
                    .last()
                    .unwrap()
                    .agent
                    .model
                    .routing_metadata_json(None),
            })
            .await;

        let result = Message::tool_result_with_call_id(
            task_call_id.clone(),
            task_function_call_id,
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
        if let Err(e) = self.session.db.complete_task_delegation_child(
            &task_call_id,
            "default",
            &report,
            failed,
            None,
        ) {
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
                def.scan_tool_results.unwrap_or_else(|| {
                    crate::agents::default_scan_tool_results(&def.name, def.mode)
                })
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
                task_function_call_id,
                result,
            } => match *result {
                Ok(completion) => {
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    if let Some(job) = self.noninteractive_jobs.get_mut(&task_call_id) {
                        if job.delivered {
                            return Ok(NoninteractiveCompletionDelivery::None);
                        }
                        job.delivered = true;
                    }
                    let result = self
                        .finalize_single_noninteractive_task(completion, tx, !was_backgrounded)
                        .await?;
                    if was_backgrounded {
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        if let Err(e) = self
                            .session
                            .db
                            .mark_task_delegation_child_delivered(&task_call_id, "default")
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
                    if let Some(job) = self.noninteractive_jobs.get_mut(&task_call_id) {
                        if job.delivered {
                            return Ok(NoninteractiveCompletionDelivery::None);
                        }
                        job.delivered = true;
                    }
                    if was_backgrounded {
                        self.record_background_noninteractive_error(&task_call_id, &body);
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        Ok(NoninteractiveCompletionDelivery::Inline(
                            Message::tool_result_with_call_id(
                                task_call_id,
                                task_function_call_id,
                                body,
                            ),
                        ))
                    }
                }
            },
            BackgroundNoninteractiveCompletion::Batch {
                task_call_id,
                task_function_call_id,
                result,
            } => match *result {
                Ok(completion) => {
                    let was_backgrounded = self
                        .noninteractive_delegations
                        .is_backgrounded_job(&task_call_id);
                    if let Some(job) = self.noninteractive_jobs.get_mut(&task_call_id) {
                        if job.delivered {
                            return Ok(NoninteractiveCompletionDelivery::None);
                        }
                        job.delivered = true;
                    }
                    let result = self
                        .finalize_batch_noninteractive_task(completion, tx)
                        .await;
                    if was_backgrounded {
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        match self
                            .session
                            .db
                            .undelivered_task_delegation_children(&task_call_id)
                        {
                            Ok(rows) => {
                                for row in rows {
                                    if let Err(e) =
                                        self.session.db.mark_task_delegation_child_delivered(
                                            &task_call_id,
                                            &row.label,
                                        )
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
                    if let Some(job) = self.noninteractive_jobs.get_mut(&task_call_id) {
                        if job.delivered {
                            return Ok(NoninteractiveCompletionDelivery::None);
                        }
                        job.delivered = true;
                    }
                    if was_backgrounded {
                        self.record_background_noninteractive_error(&task_call_id, &body);
                        Ok(self
                            .async_delegation_result(&task_call_id)
                            .map(NoninteractiveCompletionDelivery::AsyncUser)
                            .unwrap_or(NoninteractiveCompletionDelivery::None))
                    } else {
                        Ok(NoninteractiveCompletionDelivery::Inline(
                            Message::tool_result_with_call_id(
                                task_call_id,
                                task_function_call_id,
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

    pub(in crate::engine::driver) fn release_noninteractive_child_locks(
        &self,
        rows: &[crate::db::task_delegations::DelegationChildDetail],
    ) {
        let mut released = std::collections::HashSet::new();
        for row in rows {
            if !released.insert(row.child_agent.as_str()) {
                continue;
            }
            if let Err(e) = self.locks.suspend_agent(&row.child_agent, self.session.id) {
                tracing::warn!(
                    error = ?e,
                    agent = %row.child_agent,
                    task_call_id = %row.task_call_id,
                    "release noninteractive child locks after abort failed"
                );
            }
        }
    }

    pub(in crate::engine::driver) fn record_background_noninteractive_error(
        &mut self,
        task_call_id: &str,
        body: &str,
    ) {
        let rows = match self
            .session
            .db
            .list_task_delegation_children(self.session.id)
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
            if let Err(e) = self.session.db.complete_task_delegation_child(
                task_call_id,
                &row.label,
                body,
                true,
                None,
            ) {
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

    pub(in crate::engine::driver) fn background_delegation_ack(
        &mut self,
        task_call_id: &str,
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
            {
                tracing::warn!(error = %e, task_call_id, label, "mark delegation ack child delivered failed");
            }
        }
        let body = format_delegation_background_ack(task_call_id, &completed, &running);
        Message::tool_result_with_call_id(task_call_id.to_string(), task_function_call_id, body)
    }

    pub(in crate::engine::driver) fn async_delegation_result(
        &mut self,
        task_call_id: &str,
    ) -> Option<String> {
        let completed = match self
            .session
            .db
            .undelivered_task_delegation_children(task_call_id)
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

    pub(in crate::engine::driver) fn enqueue_delegation_steer(
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

    pub(in crate::engine::driver) fn dispatch_task_control(
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
                    self.release_noninteractive_child_locks(&selected);
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
                        {
                            Ok(true) => {
                                let _ = self.session.db.finish_task_assignment(
                                    self.session.id,
                                    &row.task_call_id,
                                    &row.label,
                                    "lost",
                                    None,
                                );
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
                    {
                        Ok(changed) => changed,
                        Err(e) => {
                            return format!(
                                "Error: could not cancel `{}`/`{}`: {e:#}",
                                row.task_call_id, row.label
                            );
                        }
                    };
                    let _ = self.session.db.finish_task_assignment(
                        self.session.id,
                        &row.task_call_id,
                        &row.label,
                        "cancelled",
                        None,
                    );
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
                match self.enqueue_delegation_steer(
                    Some(row.task_call_id.clone()),
                    Some(row.label.clone()),
                    body,
                    format!("agent:{}", row.task_call_id),
                    false,
                ) {
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
        let task_function_call_id = task.task_function_call_id.clone();
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
                    output_dir: entry.output_dir.as_deref(),
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
                "resume_handle": &entry.resume_handle,
                "requested_cwd": child_cwd.requested_json(),
                "resolved_cwd": child_cwd.resolved_display(),
                "output_dir": &entry.output_dir,
                "todo_ids": &entry.todo_ids,
                "skill_seed": &entry.skill_seed,
            })).collect::<Vec<_>>(),
            "why": &task.why,
        }))
        .ok();
        let parent_agent = self.stack.last().unwrap().agent.name.clone();
        if let Err(e) = self.session.db.upsert_task_delegation_job(
            self.session.id,
            &task_call_id,
            task_function_call_id.as_deref(),
            &parent_agent,
            task_args_json.as_deref(),
            &child_inits,
        ) {
            tracing::warn!(error = %e, task_call_id, "persist batch task delegation job failed");
            return Ok(Message::tool_result_with_call_id(
                task_call_id,
                task_function_call_id,
                prepend_task_repair_notes(
                    DELEGATION_PAYLOAD_REFUSAL.to_string(),
                    &task.repair_notes,
                ),
            ));
        }
        for entry in &mut task.entries {
            match self.persist_delegation_payload(
                &task_call_id,
                task_function_call_id.as_deref(),
                &parent_agent,
                &entry.label,
                &entry.child_agent,
                &entry.prompt,
            ) {
                Ok(loaded) => entry.prompt = loaded,
                Err(e) => {
                    let label = entry.label.clone();
                    tracing::warn!(error = %e, task_call_id, label, "persist batch task delegation payload failed");
                    return Ok(Message::tool_result_with_call_id(
                        task_call_id,
                        task_function_call_id,
                        prepend_task_repair_notes(
                            DELEGATION_PAYLOAD_REFUSAL.to_string(),
                            &task.repair_notes,
                        ),
                    ));
                }
            }
        }
        for entry in &task.entries {
            self.noninteractive_delegations.register_running(
                &task_call_id,
                &entry.label,
                entry.child_agent.clone(),
                NoninteractiveDelegationSnapshot::empty(),
            );
        }
        let mut runner = self.clone_for_background_noninteractive(tx);
        let complete_tx = self.noninteractive_complete_tx.clone();
        let tx_for_task = tx.clone();
        let completion_task_call_id = task_call_id.clone();
        let completion_task_function_call_id = task_function_call_id.clone();
        let handle = tokio::spawn(async move {
            let result = runner
                .execute_batch_noninteractive_task(task, &tx_for_task, cancel)
                .await;
            let _ = complete_tx
                .send(BackgroundNoninteractiveCompletion::Batch {
                    task_call_id: completion_task_call_id,
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
                    {
                        tracing::warn!(error = %e, task_call_id, label, "background batch task delegation failed");
                    }
                }
                let ack =
                    self.background_delegation_ack(&task_call_id, task_function_call_id.clone());
                if let Some(parent) = self.stack.last_mut() {
                    parent.history.push(ack);
                }
                let Some(prepared) = self.prepare_queued_user_submission(first, tx).await else {
                    return Ok(Message::user(""));
                };
                self.record_queued_user_fold(&prepared, tx).await;
                Ok(crate::engine::message::build_user_message(UserSubmission {
                    kind: UserSubmissionKind::User,
                    text: self.with_time_prelude(prepared.text),
                    images: prepared.images,
                    forced_skill: None,
                    origin_principal: None,
                    job_id: None,
                    preflight_cleaned: None,
                    queue_item_ids: Vec::new(),
                    queue_target: None,
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

    pub(in crate::engine::driver) async fn execute_batch_noninteractive_task(
        &mut self,
        task: BatchNoninteractiveTask,
        tx: &mpsc::Sender<TurnEvent>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<BatchNoninteractiveCompletion> {
        let BatchNoninteractiveTask {
            entries,
            child_cwds,
            why,
            repair_notes,
            task_call_id,
            task_function_call_id,
        } = task;

        let mut batch_refusal: Option<String> = None;
        let mut child_recursions = Vec::with_capacity(entries.len());
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
            if crate::engine::builtin::is_write_capable(&child) && entry.output_dir.is_none() {
                batch_refusal = Some(format!(
                    "parallel write-capable entry `{}` (`{}`) requires `output_dir`",
                    entry.label, entry.child_agent
                ));
                break;
            }
            child_recursions.push(child_recursion);
        }
        if let Some(msg) = batch_refusal {
            return Ok(BatchNoninteractiveCompletion {
                task_call_id,
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
        let mut children = Vec::new();
        for (idx, ((mut entry, child_cwd), child_recursion)) in entries
            .into_iter()
            .zip(child_cwds)
            .zip(child_recursions)
            .enumerate()
        {
            let driver = &*self;
            let entry_why = why.clone();
            let entry_task_call_id = task_call_id.clone();
            let parent = self.stack.last().unwrap().agent.name.clone();
            let (delegation_payload_history, delivered_prompt) = match self
                .delegation_payload_delivery(
                    &task_call_id,
                    &entry.label,
                    &entry.prompt,
                    entry.child_agent != "docs",
                ) {
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
                    parent,
                    child: entry.child_agent.clone(),
                    task_call_id: task_call_id.clone(),
                    label: entry.label.clone(),
                    prompt: entry.prompt.clone(),
                    requested_cwd: child_cwd.requested.clone(),
                    resolved_cwd: Some(child_cwd.resolved_display()),
                    trusted_only: self
                        .stack
                        .last()
                        .unwrap()
                        .agent
                        .model
                        .trusted_only_enabled(),
                    model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                    routing: routing.clone(),
                })
                .await;
            let task_identity = crate::engine::task_identity::TaskProviderIdentity::for_task_call(
                &task_call_id,
                task_function_call_id.as_deref(),
            );
            if let Err(e) = self.session.record_event(
                crate::db::session_log::SessionEventKind::SubagentSpawned,
                Some(&self.stack.last().unwrap().agent.name),
                Some(&task_call_id),
                &serde_json::json!({
                    "child_agent": entry.child_agent.clone(),
                    "task_call_id": task_call_id,
                    "provider_call_id": task_identity.provider_call_id,
                    "provider_call_id_source": task_identity.provider_call_id_source,
                    "provider_identity": task_identity.event_identity_json(&task_call_id),
                    "label": entry.label.clone(),
                    "noninteractive": true,
                    "prompt": entry.prompt.clone(),
                    "why": why.clone(),
                    "model": model_selector_json(&entry.model),
                    "trusted_only": self.stack.last().unwrap().agent.model.trusted_only_enabled(),
                    "model_trusted": self.stack.last().unwrap().agent.model.is_trusted(),
                    "routing": routing,
                    "remaining_depth": entry.remaining_depth,
                    "resume_handle": entry.resume_handle.clone(),
                    "requested_cwd": child_cwd.requested_json(),
                    "resolved_cwd": child_cwd.resolved_display(),
                    "grant_tools": entry.granted_tools.clone(),
                    "seed": entry.seeds.clone(),
                    "skill_seed": entry.skill_seed.clone(),
                    "todo_ids": entry.todo_ids.clone(),
                    "output_dir": entry.output_dir.clone(),
                }),
            ) {
                tracing::warn!(error = %e, "record batch subagent_spawned event failed");
            }

            let child_cancel = cancel.clone();
            runs.push(async move {
                let mut snapshot = NoninteractiveDelegationSnapshot::empty();
                let outcome =
                    if let Some(err) =
                        grant_rejection(&child_cwd.resolved, &entry.child_agent, &entry.granted_tools)
                    {
                        DelegationChildOutcome::failed(err)
                    } else if entry.child_agent == "docs" {
                        if entry.resume_handle.is_some() {
                            DelegationChildOutcome::failed(stale_handle_error(&entry.child_agent))
                        } else {
                            match crate::engine::docs_pipeline::run(
                                &entry.prompt,
                                &driver.spawn_args_delegated_in_cwd(
                                    &child_cwd.resolved,
                                    false,
                                    Vec::new(),
                                    entry.model.clone(),
                                    child_recursion.clone(),
                                ),
                                driver.session.clone(),
                                driver.locks.clone(),
                                driver.redact.clone(),
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
                                Ok(text) => DelegationChildOutcome::ok(text),
                                Err(e) => DelegationChildOutcome::failed(format!("Error: {e:#}")),
                            }
                        }
                    } else {
                        let child = match crate::engine::builtin::load(
                            &entry.child_agent,
                            &driver.spawn_args_delegated_in_cwd(
                                &child_cwd.resolved,
                                false,
                                entry.granted_tools.clone(),
                                entry.model.clone(),
                                child_recursion.clone(),
                            ),
                        ) {
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
                        let skill_block =
                            driver.seed_skills_block(&entry.skill_seed, &entry.child_agent);
                        let mut brief = compose_subagent_brief(&entry.prompt, &entry_why);
                        if let Some(output_dir) = &entry.output_dir {
                            brief = format!(
                                "{brief}\n\nWrite constraint: keep all file writes under `{output_dir}`."
                            );
                        }
                        if !skill_block.is_empty() {
                            brief = format!("{skill_block}{brief}");
                        }
                        let brief = driver.assign_todos_to_task(
                            brief,
                            &entry.todo_ids,
                            &entry_task_call_id,
                            &entry.label,
                            &entry.child_agent,
                        );
                        let (seed_prefix, seeds_truncated) =
                            driver
                                .prefill_child_seeds(&entry.seeds, &child, &child_cwd.resolved, None)
                                .await;
                        let mut prior_history = delegation_payload_history;
                        let mut seed_prefix = seed_prefix;
                        if !seed_prefix.is_empty() {
                            prior_history.append(&mut seed_prefix);
                        }
                        let brief = if seeds_truncated {
                            format!("{brief}{SEED_PREFILL_TRUNCATION_NOTE}")
                        } else {
                            brief
                        };
                        let collector = crate::engine::seed_collector::SeedCollector::new();
                        match run_noninteractive_resumable(
                            child,
                            brief,
                            prior_history,
                            collector,
                            driver.session.clone(),
                            driver.locks.clone(),
                            driver.redact.clone(),
                            child_cwd.resolved.clone(),
                            driver.interrupts.clone(),
                            child_cancel.clone(),
                            driver.approver.clone(),
                            driver.resource_scheduler.clone(),
                            driver.loop_guard_threshold,
                            EXPLORE_MAX_TURNS,
                            Some(driver.tandem_set.clone()),
                            Some(tx.clone()),
                            Some(NoninteractiveSteerTarget::new(
                                entry_task_call_id.clone(),
                                entry.label.clone(),
                            )),
                        )
                        .await
                        {
                            Ok(outcome) => {
                                snapshot = NoninteractiveDelegationSnapshot::from_history(
                                    outcome.history.clone(),
                                );
                                DelegationChildOutcome::ok(outcome.report)
                            }
                            Err(e) => {
                                let (message, history) = e.into_parts();
                                let partial_progress = partial_progress_from_history(&history);
                                snapshot = NoninteractiveDelegationSnapshot::from_history(history);
                                DelegationChildOutcome::failed_with_progress(
                                    format!("Error: {message}"),
                                    partial_progress,
                                )
                            }
                        }
                    };
                (idx, entry, outcome, snapshot)
            });
        }

        while let Some((idx, entry, outcome, snapshot)) = runs.next().await {
            let report = self.reconcile_todo_delta(
                &task_call_id,
                &entry.label,
                &entry.child_agent,
                &outcome.report,
                outcome.failed,
            );
            if let Err(e) = self.session.record_event(
                crate::db::session_log::SessionEventKind::SubagentReport,
                Some(&entry.child_agent),
                Some(&task_call_id),
                &with_model_routing_metadata(
                    subagent_report_event_data(
                        &entry.child_agent,
                        Some(&task_call_id),
                        task_function_call_id.as_deref(),
                        &entry.label,
                        &report,
                        Some(&outcome.partial_progress),
                    ),
                    &self.stack.last().unwrap().agent.model,
                ),
            ) {
                tracing::warn!(error = %e, "record batch subagent_report event failed");
            }
            let _ = tx
                .send(TurnEvent::SubagentReport {
                    agent: entry.child_agent.clone(),
                    task_call_id: task_call_id.clone(),
                    label: entry.label.clone(),
                    report: report.clone(),
                    trusted_only: self
                        .stack
                        .last()
                        .unwrap()
                        .agent
                        .model
                        .trusted_only_enabled(),
                    model_trusted: self.stack.last().unwrap().agent.model.is_trusted(),
                    routing: self
                        .stack
                        .last()
                        .unwrap()
                        .agent
                        .model
                        .routing_metadata_json(None),
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
            task_function_call_id,
            mut children,
            repair_notes,
        } = completion;

        if children.len() == 1
            && children[0].label.is_empty()
            && children[0].child_agent.is_empty()
            && children[0].failed
        {
            return Message::tool_result_with_call_id(
                task_call_id,
                task_function_call_id,
                prepend_task_repair_notes(children.remove(0).report, &repair_notes),
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
        let result =
            Message::tool_result_with_call_id(task_call_id.clone(), task_function_call_id, body);
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
            if let Err(e) = self.session.db.complete_task_delegation_child(
                &task_call_id,
                &label,
                &report,
                failed,
                None,
            ) {
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
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    max_turns: usize,
    // Model-comparison tandem (shadow) set, forwarded so the `docs` pipeline's
    // resolver/answerer turns are shadowed when the feature is on.
    tandem: Option<crate::engine::schedule::TandemSet>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    steer_target: Option<NoninteractiveSteerTarget>,
) -> Result<String> {
    // The docs pipeline (the only other caller) neither rehydrates nor
    // seeds: a fresh transcript, no prior history, and a throwaway seed
    // collector. It only needs the report text.
    let out = run_noninteractive_resumable(
        child,
        brief,
        Vec::new(),
        crate::engine::seed_collector::SeedCollector::new(),
        session,
        locks,
        redact,
        cwd,
        interrupts,
        cancel,
        approver,
        resource_scheduler,
        loop_guard_threshold,
        max_turns,
        tandem,
        event_tx,
        steer_target,
    )
    .await?;
    Ok(out.report)
}

#[derive(Debug, Clone)]
pub(crate) struct NoninteractiveSteerTarget {
    task_call_id: String,
    label: String,
}

impl NoninteractiveSteerTarget {
    pub(crate) fn new(task_call_id: impl Into<String>, label: impl Into<String>) -> Self {
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

    fn drain(&mut self) -> Vec<TurnEvent> {
        let mut out = Vec::new();
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

/// A finished noninteractive run: the report text plus the full transcript
/// (so the driver can persist a re-query handle, GOALS §3c).
pub(crate) struct NoninteractiveOutcome {
    /// The subagent's final text + any deferred-log section.
    pub report: String,
    /// The complete `Vec<Message>` transcript (prior history + this run),
    /// persisted as a handle for read-only noninteractive subagents in
    /// normal mode.
    pub history: Vec<Message>,
}

#[derive(Debug)]
pub(crate) struct NoninteractiveRunError {
    source: anyhow::Error,
    history: Vec<Message>,
}

impl NoninteractiveRunError {
    fn new(source: anyhow::Error, history: Vec<Message>) -> Self {
        Self { source, history }
    }

    fn into_parts(self) -> (String, Vec<Message>) {
        (format!("{:#}", self.source), self.history)
    }
}

impl std::fmt::Display for NoninteractiveRunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.source)
    }
}

impl std::error::Error for NoninteractiveRunError {}

/// Run a child agent's loop to completion, optionally **rehydrated** from a
/// prior transcript (`prior_history`) and collecting any `seed` calls into
/// `seeds`. Returns the report + the full transcript. [`run_noninteractive`]
/// is the no-rehydrate, no-seed wrapper used by the `docs` pipeline.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_noninteractive_resumable(
    child: Agent,
    brief: String,
    prior_history: Vec<Message>,
    seeds: crate::engine::seed_collector::SeedCollector,
    session: Arc<Session>,
    locks: Arc<crate::locks::LockManager>,
    redact: Arc<RedactionTable>,
    cwd: std::path::PathBuf,
    interrupts: Arc<crate::engine::interrupt::InterruptHub>,
    cancel: tokio_util::sync::CancellationToken,
    approver: Option<Arc<crate::approval::Approver>>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    loop_guard_threshold: u32,
    max_turns: usize,
    // Model-comparison tandem (shadow) set (`model-comparison-tandem-
    // inference.md`). `Some(set)` when the session has model-comparison on, so
    // this leaf subagent's (`builder`/`explore`/`docs`) substantive turns are
    // shadowed too; `None`/empty disables it. Cheap clone per call.
    tandem: Option<crate::engine::schedule::TandemSet>,
    event_tx: Option<mpsc::Sender<TurnEvent>>,
    steer_target: Option<NoninteractiveSteerTarget>,
) -> std::result::Result<NoninteractiveOutcome, NoninteractiveRunError> {
    use crate::engine::agent::turn_with_backup;

    let (child_tx, child_rx) = mpsc::channel::<TurnEvent>(64);
    let forwarder = spawn_noninteractive_event_forwarder(child_rx, event_tx, steer_target.clone());

    let agent = Arc::new(child);
    // Per-turn backup-model fallback for the subagent (`per-model-
    // backup-fallback.md`): subagents inherit the *mechanism*, resolved by the
    // same model→provider→none order against the model the subagent runs on
    // (here, its own `agent.model`). Resolved once for the run — the model is
    // fixed for the subagent's lifetime, and resolution is per-turn-equivalent
    // (the subagent always tries its primary model first each turn).
    let backup_model = resolve_backup_model_for(&cwd, &agent.model);
    // Rehydration: a follow-up starts from the subagent's prior transcript,
    // so it answers with full knowledge of what it already did (GOALS §3c).
    let mut history: Vec<Message> = prior_history;
    let mut next_prompt = Message::user(brief);
    // A noninteractive subagent's own deferred-log (`plan.md §3d`). The
    // bundled leaves (explore/docs) lack `defer_to_orchestrator`, so this
    // stays empty for them; a custom subagent that holds the tool gets its
    // deferred items folded into the leaf report it returns up.
    let deferred_log = crate::engine::deferred::DeferredLog::new();

    for _ in 0..max_turns {
        if let Some(target) = &steer_target {
            match session
                .db
                .drain_task_delegation_steers(&target.task_call_id, &target.label)
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
        // Model-comparison tandem (shadow) set for this leaf subagent turn
        // (`builder`/`explore`/`docs`, `model-comparison-tandem-
        // inference.md`). Passed into `turn`, which dispatches the shadows from
        // the exact post-redaction body; a pure DB-only observer that never
        // enters the child's history or affects its loop. `None`/empty = off.
        let turn_future = turn_with_backup(
            &agent,
            backup_model.as_ref(),
            &mut history,
            next_prompt,
            session.clone(),
            locks.clone(),
            redact.clone(),
            cwd.clone(),
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
            crate::engine::tool::ContextUsageSnapshot::unavailable(),
            deferred_log.clone(),
            seeds.clone(),
            call_id,
            tandem.as_ref(),
            None,
            &child_tx,
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
            Ok(outcome) => outcome,
            Err(error) => {
                drop(child_tx);
                let _ = forwarder.await;
                return Err(NoninteractiveRunError::new(error, history));
            }
        };
        match outcome {
            TurnOutcome::Continue => {
                next_prompt = history
                    .pop()
                    .expect("Continue with empty history is unreachable");
            }
            TurnOutcome::Done => {
                drop(child_tx);
                let _ = forwarder.await;
                // No `return` tool call: fall back to wrapping the final text
                // (envelope-holding agents only — the `docs` pipeline keeps its
                // plain answer). `None` selects the fallback path.
                let report = assemble_subagent_report(&agent, &history, &deferred_log, None);
                return Ok(NoninteractiveOutcome { report, history });
            }
            TurnOutcome::Return { fields } => {
                drop(child_tx);
                let _ = forwarder.await;
                let report =
                    assemble_subagent_report(&agent, &history, &deferred_log, Some(&fields));
                return Ok(NoninteractiveOutcome { report, history });
            }
            TurnOutcome::SpawnSubagent { .. }
            | TurnOutcome::SpawnNoninteractive { .. }
            | TurnOutcome::SpawnNoninteractiveBatch { .. }
            | TurnOutcome::TaskControl { .. }
            | TurnOutcome::ToolResult { .. }
            | TurnOutcome::ScheduleAction { .. }
            | TurnOutcome::Spawn { .. }
            | TurnOutcome::Handoff { .. } => {
                // explore is a leaf without `task`/`schedule`/`handoff`; this
                // shouldn't happen, but if it does we bail rather than spin
                // (the single async-job + primary-swap authority is the main
                // driver, never a noninteractive subagent — §22 anti-runaway).
                drop(child_tx);
                let _ = forwarder.await;
                return Err(NoninteractiveRunError::new(
                    anyhow::anyhow!(
                        "noninteractive agent `{}` attempted to delegate or schedule a job",
                        agent.name
                    ),
                    history,
                ));
            }
        }
    }
    drop(child_tx);
    let _ = forwarder.await;
    Err(NoninteractiveRunError::new(
        anyhow::anyhow!(
            "noninteractive agent `{}` exceeded {max_turns} turns",
            agent.name
        ),
        history,
    ))
}
