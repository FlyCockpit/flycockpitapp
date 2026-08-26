use super::history_window::HISTORY_PAGE_ENTRIES;
use super::*;

pub(super) const HISTORY_PREFETCH_ROWS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PageRequestScope {
    Main,
    Subagent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PageRequest {
    pub(super) id: u64,
    pub(super) session_id: uuid::Uuid,
    pub(super) scope: PageRequestScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum OlderHistoryMarker {
    #[default]
    None,
    Failed,
    Exhausted,
}

impl App {
    pub(super) fn cancel_older_history_page_request(&mut self) {
        self.loading_older = None;
    }

    pub(super) fn older_history_marker_text(&self) -> Option<String> {
        let scope = self.active_page_request_scope()?;
        let dots = if self.use_emojis { "⋯" } else { "..." };
        if self
            .loading_older
            .is_some_and(|loading| loading.scope == scope)
        {
            return Some(format!("  {dots} loading earlier messages"));
        }
        match self.older_history_marker {
            OlderHistoryMarker::None => None,
            OlderHistoryMarker::Failed
                if scope == PageRequestScope::Main || self.history.has_older() =>
            {
                Some(format!(
                    "  {dots} couldn't load earlier messages - scroll again to retry"
                ))
            }
            OlderHistoryMarker::Failed => None,
            OlderHistoryMarker::Exhausted if scope == PageRequestScope::Main => {
                Some(format!("  {dots} beginning of conversation"))
            }
            OlderHistoryMarker::Exhausted => None,
        }
    }

    pub(super) fn partial_history_find_note(&self) -> Option<String> {
        if !matches!(self.transcript_view, TranscriptViewMeta::Main) || !self.history.has_older() {
            return None;
        }
        let dots = if self.use_emojis { "⋯" } else { "..." };
        Some(format!(
            "  {dots} searched loaded messages only - scroll back to load more"
        ))
    }

    pub(super) fn maybe_start_older_history_page_fetch(&mut self) {
        let Some(scope) = self.active_page_request_scope() else {
            return;
        };
        if !self.history.has_older()
            || self.loading_older.is_some()
            || !self.anchor_near_oldest_resident_entry()
        {
            return;
        }
        let Some(session_id) = self.current_session_id() else {
            return;
        };
        let Some(before_seq) = self.history.older_cursor() else {
            self.older_history_marker = OlderHistoryMarker::Failed;
            return;
        };
        let Some(endpoint) = self.attached_daemon_endpoint() else {
            self.older_history_marker = OlderHistoryMarker::Failed;
            return;
        };

        let request_id = self.next_history_page_request_id;
        self.next_history_page_request_id = self.next_history_page_request_id.wrapping_add(1);
        if self.next_history_page_request_id == 0 {
            self.next_history_page_request_id = 1;
        }
        self.loading_older = Some(PageRequest {
            id: request_id,
            session_id,
            scope,
        });
        self.older_history_marker = OlderHistoryMarker::None;
        match scope {
            PageRequestScope::Main => {
                self.async_actions.start_blocking(
                    AsyncActionKind::DaemonRpc("history.page"),
                    AsyncActionPolicy::Dedupe(AsyncActionKey::new("history.page")),
                    move || match crate::tui::agent_runner::read_history_page_blocking(
                        &endpoint,
                        session_id,
                        Some(before_seq),
                        HISTORY_PAGE_ENTRIES as u32,
                    ) {
                        Ok((entries, has_more, oldest_seq)) => {
                            Ok(AsyncActionPayload::HistoryPage {
                                request_id,
                                session_id,
                                entries: super::events::wire_history_to_entries(entries),
                                has_more,
                                oldest_seq,
                            })
                        }
                        Err(message) => Ok(AsyncActionPayload::HistoryPageError {
                            request_id,
                            session_id,
                            message,
                        }),
                    },
                );
            }
            PageRequestScope::Subagent => {
                let Some(view) = self.active_subagent_view().cloned() else {
                    self.loading_older = None;
                    return;
                };
                let task_call_id = view.task_call_id;
                let label = view.label;
                self.async_actions.start_blocking(
                    AsyncActionKind::DaemonRpc("subagent.history.page"),
                    AsyncActionPolicy::Dedupe(AsyncActionKey::new("subagent.history.page")),
                    move || match crate::tui::agent_runner::read_subagent_history_page_blocking(
                        &endpoint,
                        session_id,
                        task_call_id.clone(),
                        label.clone(),
                        Some(before_seq),
                        HISTORY_PAGE_ENTRIES as u32,
                    ) {
                        Ok((entries, has_more, oldest_seq)) => {
                            Ok(AsyncActionPayload::SubagentHistoryPage {
                                request_id,
                                session_id,
                                task_call_id,
                                label,
                                entries: super::events::wire_history_to_entries(entries),
                                has_more,
                                oldest_seq,
                            })
                        }
                        Err(message) => Ok(AsyncActionPayload::SubagentHistoryPageError {
                            request_id,
                            session_id,
                            task_call_id,
                            label,
                            message,
                        }),
                    },
                );
            }
        }
    }

    fn active_page_request_scope(&self) -> Option<PageRequestScope> {
        match self.transcript_view {
            TranscriptViewMeta::Main => Some(PageRequestScope::Main),
            TranscriptViewMeta::Subagent(_) => Some(PageRequestScope::Subagent),
        }
    }

    fn anchor_near_oldest_resident_entry(&mut self) -> bool {
        if self.chat_pinned_to_tail || self.history.is_empty() {
            return false;
        }
        let geometry = self.chat_geometry().clone();
        let anchor_row = if let Some(anchor) = self.chat_scroll_anchor {
            let Some(entry_idx) = self.history_position_for_id(anchor.entry).or_else(|| {
                (anchor.entry_position < self.history.len()).then_some(anchor.entry_position)
            }) else {
                return false;
            };
            geometry.entry_start_row(entry_idx) + anchor.row_within_entry as usize
        } else {
            let visible_full_start = super::render::chat_visible_top(
                self.chat_total_lines,
                self.chat_visible_lines.max(1),
                self.chat_scroll_offset,
            );
            visible_full_start.saturating_sub(self.chat_banner_lines)
        };
        anchor_row <= HISTORY_PREFETCH_ROWS
    }

    pub(super) fn apply_older_history_page_error(
        &mut self,
        request_id: u64,
        session_id: uuid::Uuid,
    ) {
        let Some(loading) = self.loading_older else {
            return;
        };
        if loading.id != request_id
            || loading.session_id != session_id
            || loading.scope != PageRequestScope::Main
        {
            return;
        }
        if self.current_session_id() != Some(session_id) {
            return;
        }
        self.loading_older = None;
        self.older_history_marker = OlderHistoryMarker::Failed;
    }

    pub(super) fn apply_older_history_page_result(
        &mut self,
        request_id: u64,
        session_id: uuid::Uuid,
        entries: Vec<HistoryEntry>,
        has_more: bool,
        oldest_seq: Option<i64>,
    ) {
        let Some(loading) = self.loading_older else {
            return;
        };
        if loading.id != request_id
            || loading.session_id != session_id
            || loading.scope != PageRequestScope::Main
        {
            return;
        }
        if self.current_session_id() != Some(session_id) {
            return;
        }

        self.loading_older = None;
        let accepted = self.prepend_history_page(entries, oldest_seq, has_more);
        if accepted {
            self.older_history_marker = if has_more {
                OlderHistoryMarker::None
            } else {
                OlderHistoryMarker::Exhausted
            };
        } else {
            self.older_history_marker = OlderHistoryMarker::Failed;
        }
    }
}
