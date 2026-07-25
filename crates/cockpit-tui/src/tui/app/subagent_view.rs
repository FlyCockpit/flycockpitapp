use super::history_window::{HISTORY_WINDOW_TARGET_ENTRIES, HistoryWindow};
use super::*;

fn subagent_view_notice(read_only: bool, truncated: bool) -> Option<String> {
    let mut parts = Vec::new();
    if read_only {
        parts.push("This subagent is read-only.".to_string());
    }
    if truncated {
        parts.push(format!(
            "Showing the most recent {HISTORY_WINDOW_TARGET_ENTRIES} messages - older subagent history is not loaded (use /export for the full transcript)."
        ));
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

impl App {
    fn capture_transcript_view(&mut self) -> StoredTranscriptView {
        let history_render_cache_rows = self.history_render_cache_rows;
        let history_render_cache = self.take_history_render_cache();
        StoredTranscriptView {
            meta: std::mem::take(&mut self.transcript_view),
            history: std::mem::take(&mut self.history),
            pending: self.pending.take(),
            history_render_versions: std::mem::take(&mut self.history_render_versions),
            history_render_fingerprints: std::mem::take(&mut self.history_render_fingerprints),
            history_render_cache,
            history_render_cache_rows,
            pending_render_cache: self.pending_render_cache.take(),
            chat_scroll_offset: self.chat_scroll_offset,
            chat_scroll_anchor: self.chat_scroll_anchor,
            chat_pinned_to_tail: self.chat_pinned_to_tail,
        }
    }

    fn restore_transcript_view(&mut self, mut view: StoredTranscriptView) {
        self.transcript_view = std::mem::take(&mut view.meta);
        self.history = std::mem::take(&mut view.history);
        self.pending = view.pending.take();
        self.history_render_versions = std::mem::take(&mut view.history_render_versions);
        self.history_render_fingerprints = std::mem::take(&mut view.history_render_fingerprints);
        self.restore_history_render_cache(
            std::mem::take(&mut view.history_render_cache),
            view.history_render_cache_rows,
        );
        self.pending_render_cache = view.pending_render_cache.take();
        self.restore_chat_scroll_state(
            view.chat_scroll_offset,
            view.chat_scroll_anchor,
            view.chat_pinned_to_tail,
        );
        self.mark_chat_geometry_dirty_from(0);
        self.chat_find_lines.clear();
        self.chat_find_lines_query = None;
        self.chat_row_meta.clear();
        self.clickable_rows.clear();
        self.box_rows.clear();
        self.diff_rows.clear();
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
    }

    pub(super) fn active_subagent_view(&self) -> Option<&SubagentViewMeta> {
        match &self.transcript_view {
            TranscriptViewMeta::Subagent(view) => Some(view),
            TranscriptViewMeta::Main => None,
        }
    }

    pub(super) fn active_subagent_view_mut(&mut self) -> Option<&mut SubagentViewMeta> {
        match &mut self.transcript_view {
            TranscriptViewMeta::Subagent(view) => Some(view),
            TranscriptViewMeta::Main => None,
        }
    }

    pub(super) fn open_subagent_view_for_history_index(&mut self, idx: usize) -> bool {
        let Some(HistoryEntry::Subagent {
            parent,
            child,
            task_call_id,
            label,
            outcome,
            ..
        }) = self.history.get(idx).cloned()
        else {
            return false;
        };

        let session_id = self.current_session_id();
        let fetch_task_call_id = task_call_id.clone();
        let fetch_label = label.clone();
        let read_only = outcome.is_some() || child == "docs";
        let finished = outcome.is_some();
        let meta = SubagentViewMeta {
            parent,
            child,
            task_call_id,
            label,
            read_only,
            finished,
            countdown_started: None,
            countdown_cancelled: true,
            notice: subagent_view_notice(read_only && outcome.is_none(), false),
        };

        let previous = self.capture_transcript_view();
        self.transcript_view_stack.push(previous);
        self.transcript_view = TranscriptViewMeta::Subagent(meta);
        self.history = Vec::new().into();
        self.pending = None;
        self.history_render_versions = std::collections::HashMap::new();
        self.history_render_fingerprints = std::collections::HashMap::new();
        self.history_render_cache_clear();
        self.pending_render_cache = None;
        self.pin_chat_to_tail();
        self.mark_chat_geometry_dirty_from(0);
        self.chat_find_lines.clear();
        self.chat_find_lines_query = None;
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
        if let Some(session_id) = session_id {
            self.start_subagent_history_fetch(session_id, fetch_task_call_id, fetch_label);
        }
        true
    }

    fn start_subagent_history_fetch(
        &mut self,
        session_id: uuid::Uuid,
        task_call_id: String,
        label: String,
    ) {
        let db = self.startup_background.db.clone();
        let key = format!("subagent.history:{session_id}:{task_call_id}:{label}");
        self.async_actions.start(
            AsyncActionKind::Internal("subagent.history"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(key)),
            async move {
                let history = match db {
                    Some(db) => {
                        let query_task_call_id = task_call_id.clone();
                        let query_label = label.clone();
                        let snapshot = db
                            .read(move |conn| {
                                cockpit_core::engine::rehydrate::subagent_history_snapshot_conn(
                                    conn,
                                    session_id,
                                    &query_task_call_id,
                                    &query_label,
                                )
                            })
                            .await
                            .map_err(|e| e.to_string())?;
                        wire_history_to_entries(snapshot)
                    }
                    None => Vec::new(),
                };
                Ok(AsyncActionPayload::SubagentHistory {
                    session_id,
                    task_call_id,
                    label,
                    history,
                })
            },
        );
    }

    pub(super) fn apply_subagent_history_result(
        &mut self,
        session_id: uuid::Uuid,
        task_call_id: &str,
        label: &str,
        history: Vec<HistoryEntry>,
    ) {
        if self.current_session_id() != Some(session_id) {
            return;
        }
        let Some(view) = self.active_subagent_view() else {
            return;
        };
        if view.task_call_id != task_call_id || view.label != label {
            return;
        }
        let window = HistoryWindow::from_capped_newest(history, HISTORY_WINDOW_TARGET_ENTRIES);
        let truncated = window.has_older();
        self.history = window;
        if let Some(view) = self.active_subagent_view_mut() {
            view.notice = subagent_view_notice(view.read_only && !view.finished, truncated);
        }
        self.history_render_versions = std::collections::HashMap::new();
        self.history_render_fingerprints = std::collections::HashMap::new();
        self.history_render_cache_clear();
        self.pending_render_cache = None;
        self.pin_chat_to_tail();
        self.mark_chat_geometry_dirty_from(0);
        self.chat_find_lines.clear();
        self.chat_find_lines_query = None;
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
    }

    pub(super) fn return_from_subagent_view(&mut self) -> bool {
        let Some(previous) = self.transcript_view_stack.pop() else {
            return false;
        };
        self.restore_transcript_view(previous);
        true
    }

    pub(super) fn cancel_subagent_countdown_or_return(&mut self) -> bool {
        if let Some(view) = self.active_subagent_view_mut()
            && view.countdown_started.is_some()
            && !view.countdown_cancelled
        {
            view.countdown_cancelled = true;
            view.notice = Some("Stayed in finished subagent view.".to_string());
            return true;
        }
        self.return_from_subagent_view()
    }

    pub(super) fn refresh_subagent_countdown(&mut self) {
        let should_return = self
            .active_subagent_view()
            .and_then(|view| {
                view.countdown_started
                    .map(|started| (started, view.countdown_cancelled))
            })
            .is_some_and(|(started, cancelled)| {
                !cancelled && started.elapsed() >= Duration::from_secs(5)
            });
        if should_return {
            let _ = self.return_from_subagent_view();
        }
    }

    pub(super) fn active_subagent_countdown_line(&self) -> Option<String> {
        let view = self.active_subagent_view()?;
        let started = view.countdown_started?;
        if view.countdown_cancelled {
            return None;
        }
        let elapsed = started.elapsed().as_secs();
        let remaining = 5_u64.saturating_sub(elapsed).max(1);
        Some(format!(
            "Returning to {} from {} in {remaining}s - press esc to stay here",
            view.parent, view.child
        ))
    }

    pub(super) fn submit_subagent_steer(&mut self) -> bool {
        let Some(view) = self.active_subagent_view().cloned() else {
            return false;
        };
        let message = self.composer.text().trim().to_string();
        if message.is_empty() {
            return true;
        }
        if view.read_only || view.finished {
            if let Some(active) = self.active_subagent_view_mut() {
                active.notice =
                    Some("This subagent is read-only; steering is disabled.".to_string());
            }
            return true;
        }
        let Some(session_id) = self.current_session_id() else {
            if let Some(active) = self.active_subagent_view_mut() {
                active.notice = Some("No active session; steer was not sent.".to_string());
            }
            return true;
        };
        self.composer.clear();
        self.history.push(HistoryEntry::User {
            text: message.clone(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            preflight_pending: false,
            persist_failed: false,
        });
        self.push_plain("steer queued for next turn boundary".to_string());
        let req = cockpit_core::daemon::proto::Request::SteerDelegation {
            session_id,
            task_call_id: view.task_call_id,
            label: view.label,
            message,
        };
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("subagent.steer"),
            AsyncActionPolicy::AllowConcurrent,
            move || match agent_runner::daemon_request_blocking(req)? {
                cockpit_core::daemon::proto::Response::DelegationSteer { result } => {
                    Ok(AsyncActionPayload::DelegationSteer(result))
                }
                other => Err(format!("unexpected steer response: {other:?}")),
            },
        );
        true
    }

    pub(super) fn apply_subagent_steer_result(
        &mut self,
        result: cockpit_core::daemon::proto::DelegationSteerResult,
    ) {
        let line = match result.status {
            cockpit_core::daemon::proto::DelegationSteerStatus::Queued => {
                let label = result.label.clone().unwrap_or_default();
                format!(
                    "steer queued for {}/{} at next turn boundary",
                    result.task_call_id, label
                )
            }
            cockpit_core::daemon::proto::DelegationSteerStatus::NotSteerable => {
                format!("steer not queued: {}", result.message)
            }
            cockpit_core::daemon::proto::DelegationSteerStatus::InternalError => {
                format!("steer failed: {}", result.message)
            }
        };
        match result.status {
            cockpit_core::daemon::proto::DelegationSteerStatus::Queued => {
                if let Some(view) = self.active_subagent_view_mut() {
                    view.notice = Some(line);
                } else {
                    self.show_toast(line, ToastKind::Success);
                }
            }
            cockpit_core::daemon::proto::DelegationSteerStatus::NotSteerable => {
                if let Some(view) = self.active_subagent_view_mut() {
                    view.read_only = true;
                    view.finished = true;
                    view.notice = Some(line);
                    if view.countdown_started.is_none() {
                        view.countdown_started = Some(Instant::now());
                        view.countdown_cancelled = false;
                    }
                } else {
                    self.show_toast(line, ToastKind::Warning);
                }
            }
            cockpit_core::daemon::proto::DelegationSteerStatus::InternalError => {
                if let Some(view) = self.active_subagent_view_mut() {
                    view.notice = Some(line);
                } else {
                    self.show_toast(line, ToastKind::Error);
                }
            }
        }
    }
}
