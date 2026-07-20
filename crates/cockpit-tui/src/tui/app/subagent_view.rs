use super::*;

impl App {
    fn capture_transcript_view(&mut self) -> StoredTranscriptView {
        StoredTranscriptView {
            meta: std::mem::take(&mut self.transcript_view),
            history: std::mem::take(&mut self.history),
            pending: self.pending.take(),
            history_render_versions: std::mem::take(&mut self.history_render_versions),
            history_render_fingerprints: std::mem::take(&mut self.history_render_fingerprints),
            history_render_cache: std::mem::take(&mut self.history_render_cache),
            pending_render_cache: self.pending_render_cache.take(),
            chat_scroll_offset: self.chat_scroll_offset,
        }
    }

    fn restore_transcript_view(&mut self, mut view: StoredTranscriptView) {
        self.transcript_view = std::mem::take(&mut view.meta);
        self.history = std::mem::take(&mut view.history);
        self.pending = view.pending.take();
        self.history_render_versions = std::mem::take(&mut view.history_render_versions);
        self.history_render_fingerprints = std::mem::take(&mut view.history_render_fingerprints);
        self.history_render_cache = std::mem::take(&mut view.history_render_cache);
        self.pending_render_cache = view.pending_render_cache.take();
        self.chat_scroll_offset = view.chat_scroll_offset;
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

        let history = self.backfill_subagent_history(&task_call_id, &label);
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
            notice: if read_only && outcome.is_none() {
                Some("This subagent is read-only.".to_string())
            } else {
                None
            },
        };

        let previous = self.capture_transcript_view();
        self.transcript_view_stack.push(previous);
        self.transcript_view = TranscriptViewMeta::Subagent(meta);
        self.history = history;
        self.pending = None;
        self.history_render_versions = vec![0; self.history.len()];
        self.history_render_fingerprints = vec![0; self.history.len()];
        self.history_render_cache.clear();
        self.pending_render_cache = None;
        self.chat_scroll_offset = 0;
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
        true
    }

    fn backfill_subagent_history(&self, task_call_id: &str, label: &str) -> Vec<HistoryEntry> {
        let Some(session_id) = self.current_session_id() else {
            return Vec::new();
        };
        let snapshot = cockpit_db::Db::open_default()
            .and_then(|db| {
                db.read_blocking(|conn| {
                    cockpit_core::engine::rehydrate::subagent_history_snapshot_conn(
                        conn,
                        session_id,
                        task_call_id,
                        label,
                    )
                })
            })
            .unwrap_or_default();
        wire_history_to_entries(snapshot)
    }

    pub(super) fn return_from_subagent_view(&mut self) -> bool {
        let Some(previous) = self.transcript_view_stack.pop() else {
            return false;
        };
        self.restore_transcript_view(previous);
        self.chat_scroll_offset = 0;
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
        self.history_render_versions.resize(self.history.len(), 0);
        self.history_render_fingerprints
            .resize(self.history.len(), 0);
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
