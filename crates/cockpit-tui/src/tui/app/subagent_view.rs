use super::history_window::{HISTORY_WINDOW_TARGET_ENTRIES, HistoryWindow};
use super::*;

fn subagent_steer_message(
    composer: &crate::tui::composer::RegisteredComposer,
) -> Result<Option<String>, &'static str> {
    let Some(message) = composer.plain_payload() else {
        return Err(
            "Subagent steering does not accept image attachments; remove them before sending.",
        );
    };
    let message = message.trim().to_string();
    Ok((!message.is_empty()).then_some(message))
}

#[cfg(test)]
mod tests {
    use super::subagent_steer_message;
    use crate::tui::composer::RegisteredComposer;

    #[test]
    fn condensed_text_steer_expands_payload_instead_of_sending_placeholder() {
        let mut composer = RegisteredComposer::new(false);
        composer.insert_registered_text("actual steering text".to_string(), 3);
        let message = subagent_steer_message(&composer)
            .expect("text paste is supported")
            .expect("message is non-empty");
        assert_eq!(message, "actual steering text");
        assert!(!message.contains("[Pasted text"));
    }

    #[test]
    fn image_steer_fails_closed_without_losing_registry_authority() {
        let mut composer = RegisteredComposer::new(false);
        composer.insert_registered_image(vec![1, 2, 3]);
        let error = subagent_steer_message(&composer).expect_err("images unsupported");
        assert!(error.contains("does not accept image attachments"));
        assert_eq!(composer.test_paste_blocks().len(), 1);
    }
}

fn subagent_view_notice(read_only: bool, truncated: bool) -> Option<String> {
    let mut parts = Vec::new();
    if read_only {
        parts.push("This subagent is read-only.".to_string());
    }
    if truncated {
        parts.push(format!(
            "Showing the most recent {HISTORY_WINDOW_TARGET_ENTRIES} messages - scroll up to load older messages."
        ));
    }
    (!parts.is_empty()).then(|| parts.join(" "))
}

impl App {
    fn capture_transcript_view(&mut self) -> StoredTranscriptView {
        self.cancel_older_history_page_request();
        let history_render_cache_rows = self.history_render_cache_rows;
        let history_render_cache = self.take_history_render_cache();
        StoredTranscriptView {
            meta: std::mem::take(&mut self.transcript_view),
            history: std::mem::take(&mut self.history),
            pending: self.pending.take(),
            active_display_attempt_id: self.active_display_attempt_id.take(),
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
        self.cancel_older_history_page_request();
        self.transcript_view = std::mem::take(&mut view.meta);
        self.history = std::mem::take(&mut view.history);
        self.pending = view.pending.take();
        self.active_display_attempt_id = view.active_display_attempt_id.take();
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
        let Some(endpoint) = self.attached_daemon_endpoint() else {
            self.push_plain(
                "Subagent history unavailable — reconnect to the daemon, then Retry".to_string(),
            );
            return;
        };
        let key = format!("subagent.history:{session_id}:{task_call_id}:{label}");
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("subagent.history"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(key)),
            move || {
                let request = cockpit_proto::Request::ReadSubagentHistoryPage {
                    session_id,
                    task_call_id: task_call_id.clone(),
                    label: label.clone(),
                    before_seq: None,
                    limit: HISTORY_WINDOW_TARGET_ENTRIES as u32,
                };
                let response =
                    crate::tui::agent_runner::daemon_request_at_blocking(&endpoint, request)?;
                let cockpit_proto::Response::SubagentHistoryPage {
                    entries,
                    has_more,
                    oldest_seq,
                    ..
                } = response
                else {
                    return Err(format!(
                        "unexpected subagent history response: {response:?}"
                    ));
                };
                Ok(AsyncActionPayload::SubagentHistory {
                    session_id,
                    task_call_id,
                    label,
                    history: wire_history_to_entries(entries),
                    has_more,
                    oldest_seq,
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
        has_more: bool,
        oldest_seq: Option<i64>,
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
        let window = HistoryWindow::from_history_page(history, oldest_seq, has_more);
        self.history = window;
        self.older_history_marker = super::scrollback_page_in::OlderHistoryMarker::None;
        if let Some(view) = self.active_subagent_view_mut() {
            view.notice = subagent_view_notice(view.read_only && !view.finished, has_more);
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

    pub(super) fn apply_subagent_history_page_error(
        &mut self,
        request_id: u64,
        session_id: uuid::Uuid,
        task_call_id: &str,
        label: &str,
    ) {
        let Some(loading) = self.loading_older else {
            return;
        };
        if loading.id != request_id
            || loading.session_id != session_id
            || loading.scope != super::scrollback_page_in::PageRequestScope::Subagent
        {
            return;
        }
        if self.current_session_id() != Some(session_id) {
            return;
        }
        let Some(view) = self.active_subagent_view() else {
            return;
        };
        if view.task_call_id != task_call_id || view.label != label {
            return;
        }
        self.loading_older = None;
        self.older_history_marker = super::scrollback_page_in::OlderHistoryMarker::Failed;
    }

    pub(super) fn apply_subagent_history_page_result(
        &mut self,
        request_id: u64,
        session_id: uuid::Uuid,
        subagent_key: (&str, &str),
        entries: Vec<HistoryEntry>,
        has_more: bool,
        oldest_seq: Option<i64>,
    ) {
        let (task_call_id, label) = subagent_key;
        let Some(loading) = self.loading_older else {
            return;
        };
        if loading.id != request_id
            || loading.session_id != session_id
            || loading.scope != super::scrollback_page_in::PageRequestScope::Subagent
        {
            return;
        }
        if self.current_session_id() != Some(session_id) {
            return;
        }
        let Some(view) = self.active_subagent_view() else {
            return;
        };
        if view.task_call_id != task_call_id || view.label != label {
            return;
        }

        self.loading_older = None;
        let accepted = self.prepend_history_page(entries, oldest_seq, has_more);
        self.older_history_marker = if accepted {
            super::scrollback_page_in::OlderHistoryMarker::None
        } else {
            super::scrollback_page_in::OlderHistoryMarker::Failed
        };
        let has_older = self.history.has_older();
        if accepted && let Some(view) = self.active_subagent_view_mut() {
            view.notice = subagent_view_notice(view.read_only && !view.finished, has_older);
        }
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
        let message = match subagent_steer_message(&self.composer) {
            Ok(Some(message)) => message,
            Ok(None) => return true,
            Err(error) => {
                if let Some(active) = self.active_subagent_view_mut() {
                    active.notice = Some(error.to_string());
                }
                return true;
            }
        };
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
        let Some(endpoint) = self.attached_daemon_endpoint() else {
            self.push_plain("Subagent steering unavailable — daemon is not attached".to_string());
            return true;
        };
        let req = cockpit_proto::Request::SteerDelegation {
            session_id,
            task_call_id: view.task_call_id,
            label: view.label,
            message: message.clone(),
        };
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("subagent.steer"),
            AsyncActionPolicy::AllowConcurrent,
            move || match agent_runner::daemon_request_at_blocking(&endpoint, req)? {
                cockpit_proto::Response::DelegationSteer { result } => {
                    Ok(AsyncActionPayload::DelegationSteer(result))
                }
                other => Err(format!("unexpected steer response: {other:?}")),
            },
        );
        self.clear_composer_buffer();
        self.history.push(HistoryEntry::User {
            text: message,
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            optimistic_submission_id: None,
            preflight_pending: false,
            persist_failed: false,
        });
        self.push_plain("steer queued for next turn boundary".to_string());
        true
    }

    pub(super) fn apply_subagent_steer_result(
        &mut self,
        result: cockpit_proto::DelegationSteerResult,
    ) {
        let line = match result.status {
            cockpit_proto::DelegationSteerStatus::Queued => {
                let label = result.label.clone().unwrap_or_default();
                format!(
                    "steer queued for {}/{} at next turn boundary",
                    result.task_call_id, label
                )
            }
            cockpit_proto::DelegationSteerStatus::NotSteerable => {
                format!("steer not queued: {}", result.message)
            }
            cockpit_proto::DelegationSteerStatus::InternalError => {
                format!("steer failed: {}", result.message)
            }
        };
        match result.status {
            cockpit_proto::DelegationSteerStatus::Queued => {
                if let Some(view) = self.active_subagent_view_mut() {
                    view.notice = Some(line);
                } else {
                    self.show_toast(line, ToastKind::Success);
                }
            }
            cockpit_proto::DelegationSteerStatus::NotSteerable => {
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
            cockpit_proto::DelegationSteerStatus::InternalError => {
                if let Some(view) = self.active_subagent_view_mut() {
                    view.notice = Some(line);
                } else {
                    self.show_toast(line, ToastKind::Error);
                }
            }
        }
    }
}
