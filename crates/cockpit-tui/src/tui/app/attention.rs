use super::*;

impl App {
    /// Show a transient toast (TUI-design-philosophy §7). Replaces
    /// any existing toast — newest wins, the older one is gone.
    /// 3-second TTL; cleared early by any user interaction (see the
    /// `dismiss_toast_on_interaction` hooks in handle_key and
    /// handle_mouse).
    pub(super) fn show_toast(&mut self, text: impl Into<String>, kind: ToastKind) {
        self.toast = Some(Toast {
            text: text.into(),
            kind,
            expires_at: Instant::now() + TOAST_TTL,
            persistent: false,
        });
    }

    pub(super) fn apply_idle_reason_status(&mut self, reason: crate::engine::IdleReason) {
        self.idle_reason_status = idle_reason_status(reason);
    }

    #[cfg(test)]
    pub(super) fn idle_reason_status_text(&self) -> Option<&str> {
        self.idle_reason_status
            .as_ref()
            .map(|status| status.text.as_str())
    }

    pub(super) fn push_plain(&mut self, line: impl Into<String>) {
        self.history.push(HistoryEntry::Plain { line: line.into() });
    }

    /// Run one attention event (implementation note) through
    /// the pure decision layer and apply the result: in-TUI toast, optional
    /// terminal bell, optional desktop notification. Never blocks the event
    /// loop and never enters the model's context — these are user-facing only.
    ///
    /// The decision (classification + debounce + focus policy) is computed by
    /// [`crate::tui::attention::decide`], a pure function tested in isolation;
    /// this method only performs the side effects it asks for, each of which
    /// is failure-tolerant.
    pub(super) fn notify_attention(&mut self, event: crate::tui::attention::AttentionEvent) {
        self.apply_attention_decision(event, false, true, 1);
    }

    pub(super) fn apply_attention_decision(
        &mut self,
        event: crate::tui::attention::AttentionEvent,
        persistent_toast: bool,
        show_toast: bool,
        waiting_count: usize,
    ) {
        use crate::tui::attention::{NoticeKind, TitleDecision, decide};
        let now = Instant::now();
        // "Recently interacted" — a conservative focus proxy. Terminals can't
        // reliably report focus, so we treat a keystroke within the last few
        // seconds as "the user is here watching."
        let recently_interacted =
            now.duration_since(self.last_user_interaction) < RECENT_INTERACTION_WINDOW;
        let decision = decide(
            event,
            &self.attention,
            recently_interacted,
            waiting_count,
            now,
            &mut self.attention_state,
        );
        if decision.is_noop() {
            return;
        }
        if show_toast && let Some((text, kind)) = decision.toast {
            let toast_kind = match kind {
                NoticeKind::Info => ToastKind::Info,
                NoticeKind::Success => ToastKind::Success,
                NoticeKind::Error => ToastKind::Error,
            };
            self.toast = Some(Toast {
                text: text.to_string(),
                kind: toast_kind,
                expires_at: Instant::now() + TOAST_TTL,
                persistent: persistent_toast,
            });
        }
        if decision.bell {
            ring_terminal_bell();
        }
        if decision.desktop {
            post_desktop_notification(event.toast_text());
        }
        match decision.title {
            TitleDecision::Set(title) => self.set_terminal_title_marker(&title),
            TitleDecision::Clear => self.clear_terminal_title_marker(),
            TitleDecision::Unchanged => {}
        }
    }

    pub(super) fn raise_attention_interrupt(
        &mut self,
        session_id: uuid::Uuid,
        interrupt_id: uuid::Uuid,
        kind: AttentionInterruptKind,
        pending_count: usize,
    ) {
        let event = kind.event();
        let state = AttentionInterruptState {
            interrupt_id,
            kind,
            pending: true,
            pending_count,
            next_renudge_at: Instant::now() + crate::tui::attention::RENUDGE_INTERVAL,
        };
        let foreground = self.current_session_id() == Some(session_id);
        if foreground {
            self.attention_interrupt = Some(state);
        } else {
            self.background_attention_interrupts
                .insert(session_id, state);
        }
        let visible = foreground && self.foreground_interrupt_visible();
        self.apply_attention_decision(event, !visible, !visible, self.attention_waiting_count());
    }

    pub(super) fn resolve_attention_interrupt(&mut self) {
        self.attention_interrupt = None;
        self.refresh_attention_interrupt_surfaces();
    }

    pub(super) fn resolve_attention_interrupt_for(
        &mut self,
        session_id: uuid::Uuid,
        interrupt_id: uuid::Uuid,
    ) {
        if self.current_session_id() == Some(session_id)
            && self
                .attention_interrupt
                .as_ref()
                .is_some_and(|state| state.interrupt_id == interrupt_id)
        {
            self.attention_interrupt = None;
        }
        self.background_attention_interrupts
            .retain(|sid, state| *sid != session_id || state.interrupt_id != interrupt_id);
        self.refresh_attention_interrupt_surfaces();
    }

    pub(super) fn refresh_attention_interrupt_surfaces(&mut self) {
        let foreground_visible = self.foreground_interrupt_visible();
        let persistent_toast_needed = !self.background_attention_interrupts.is_empty()
            || (self.attention_interrupt.is_some() && !foreground_visible);
        let Some(kind) = self
            .attention_interrupt
            .as_ref()
            .map(|state| state.kind)
            .or_else(|| {
                self.background_attention_interrupts
                    .values()
                    .next()
                    .map(|state| state.kind)
            })
        else {
            if self.toast.as_ref().is_some_and(|toast| toast.persistent) {
                self.toast = None;
            }
            self.clear_terminal_title_marker();
            return;
        };
        if !persistent_toast_needed && self.toast.as_ref().is_some_and(|toast| toast.persistent) {
            self.toast = None;
        }
        self.apply_attention_decision(kind.event(), true, false, self.attention_waiting_count());
    }

    pub(super) fn foreground_interrupt_visible(&self) -> bool {
        self.question_dialog.is_some() && !self.overlay.is_open() && self.keys_overlay.is_none()
    }

    pub(super) fn attention_waiting_count(&self) -> usize {
        let foreground_count = self
            .attention_interrupt
            .as_ref()
            .filter(|state| state.pending)
            .map(|state| state.pending_count.saturating_add(1))
            .unwrap_or(0);
        foreground_count
            + self
                .background_attention_interrupts
                .values()
                .filter(|state| state.pending)
                .map(|state| state.pending_count.saturating_add(1))
                .sum::<usize>()
    }

    pub(super) fn update_background_attention_interrupt(
        &mut self,
        session_id: uuid::Uuid,
        active_interrupt_id: Option<uuid::Uuid>,
        pending_count: usize,
    ) {
        match active_interrupt_id {
            Some(active) => {
                if let Some(state) = self.background_attention_interrupts.get_mut(&session_id) {
                    state.interrupt_id = active;
                    state.pending_count = pending_count;
                }
            }
            None => {
                self.background_attention_interrupts.remove(&session_id);
            }
        }
        self.refresh_attention_interrupt_surfaces();
    }

    pub(super) fn update_foreground_attention_interrupt(
        &mut self,
        active_interrupt_id: Option<uuid::Uuid>,
        pending_count: usize,
    ) {
        match (self.question_dialog.as_mut(), active_interrupt_id) {
            (Some(dialog), Some(active)) if dialog.interrupt_id() == active => {
                dialog.set_pending_count(pending_count);
                if let Some(state) = self.attention_interrupt.as_mut() {
                    state.interrupt_id = active;
                    state.pending_count = pending_count;
                }
                self.refresh_attention_interrupt_surfaces();
            }
            (Some(_), None) => {
                self.question_dialog = None;
                self.resolve_attention_interrupt();
            }
            (Some(_), Some(_)) => {
                self.question_dialog = None;
                self.resolve_attention_interrupt();
            }
            _ => {}
        }
    }

    pub(super) fn tick_attention_interrupt(&mut self) -> bool {
        let now = Instant::now();
        let mut nudge = None;
        let foreground_visible = self.foreground_interrupt_visible();
        if let Some(state) = self.attention_interrupt.as_mut()
            && state.pending
            && now >= state.next_renudge_at
        {
            state.next_renudge_at = now + crate::tui::attention::RENUDGE_INTERVAL;
            nudge = Some((state.kind, !foreground_visible, !foreground_visible));
        }
        if nudge.is_none()
            && let Some(state) = self
                .background_attention_interrupts
                .values_mut()
                .find(|state| state.pending && now >= state.next_renudge_at)
        {
            state.next_renudge_at = now + crate::tui::attention::RENUDGE_INTERVAL;
            nudge = Some((state.kind, true, true));
        }
        let Some((kind, persistent_toast, show_toast)) = nudge else {
            return false;
        };
        self.apply_attention_decision(
            kind.event(),
            persistent_toast,
            show_toast,
            self.attention_waiting_count(),
        );
        true
    }

    pub(super) fn set_terminal_title_marker(&mut self, title: &str) {
        if !self.attention.title {
            return;
        }
        if !self.terminal_title.stack_pushed {
            emit_terminal_title_sequence(&crate::tui::attention::terminal_title_marker_escapes(
                title,
            ));
            self.terminal_title.stack_pushed = true;
            self.terminal_title
                .pushed_for_cleanup
                .store(true, Ordering::SeqCst);
        } else {
            emit_terminal_title_sequence(&crate::tui::attention::terminal_title_set_escapes(title));
        }
        self.terminal_title.active = true;
    }

    pub(super) fn clear_terminal_title_marker(&mut self) {
        if !self.terminal_title.active {
            return;
        }
        emit_terminal_title_sequence(&crate::tui::attention::terminal_title_restore_escapes(
            self.terminal_title.stack_pushed,
        ));
        self.terminal_title.active = false;
        self.terminal_title.stack_pushed = false;
        self.terminal_title
            .pushed_for_cleanup
            .store(false, Ordering::SeqCst);
    }

    /// Drop the toast if it has expired. Called once per event-loop
    /// tick so a toast left untouched for 3 seconds cleans itself
    /// up without needing a new event to fire.
    pub(super) fn tick_toast(&mut self) -> bool {
        if let Some(toast) = &self.toast
            && !toast.persistent
            && Instant::now() > toast.expires_at
        {
            self.toast = None;
            return true;
        }
        false
    }
}
