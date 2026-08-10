use std::ops::{Deref, Index, IndexMut};

use super::{App, DirtyScan, HistoryEntry, HistoryLog};

pub(in crate::tui) const HISTORY_WINDOW_TARGET_ENTRIES: usize = 600;
pub(in crate::tui) const HISTORY_PAGE_ENTRIES: usize = 200;

#[derive(Debug, Clone, Default)]
pub(in crate::tui) struct HistoryWindow {
    log: HistoryLog,
    older_cursor: Option<i64>,
    has_older: bool,
}

impl From<Vec<HistoryEntry>> for HistoryWindow {
    fn from(entries: Vec<HistoryEntry>) -> Self {
        Self {
            log: entries.into(),
            older_cursor: None,
            has_older: false,
        }
    }
}

impl Deref for HistoryWindow {
    type Target = HistoryLog;

    fn deref(&self) -> &Self::Target {
        &self.log
    }
}

impl Index<usize> for HistoryWindow {
    type Output = HistoryEntry;

    fn index(&self, index: usize) -> &Self::Output {
        &self.log[index]
    }
}

impl IndexMut<usize> for HistoryWindow {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.log[index]
    }
}

impl<'a> IntoIterator for &'a HistoryWindow {
    type Item = &'a HistoryEntry;
    type IntoIter = std::slice::Iter<'a, HistoryEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.log.iter()
    }
}

impl HistoryWindow {
    pub(super) fn as_slice(&self) -> &[HistoryEntry] {
        &self.log
    }

    pub(super) fn from_history_page(
        entries: Vec<HistoryEntry>,
        older_cursor: Option<i64>,
        has_older: bool,
    ) -> Self {
        Self {
            log: entries.into(),
            older_cursor,
            has_older,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn older_cursor(&self) -> Option<i64> {
        self.older_cursor
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn has_older(&self) -> bool {
        self.has_older
    }

    pub(super) fn push(&mut self, entry: HistoryEntry) {
        self.log.push(entry);
    }

    pub(super) fn insert(&mut self, idx: usize, entry: HistoryEntry) {
        self.log.insert(idx, entry);
    }

    pub(super) fn remove(&mut self, idx: usize) -> HistoryEntry {
        self.log.remove(idx)
    }

    pub(super) fn clear(&mut self) {
        self.log.clear();
        self.older_cursor = None;
        self.has_older = false;
    }

    pub(super) fn extend<I: IntoIterator<Item = HistoryEntry>>(&mut self, entries: I) {
        self.log.extend(entries);
    }

    #[allow(dead_code)]
    pub(super) fn truncate(&mut self, len: usize) {
        self.log.truncate(len);
        if len == 0 {
            self.older_cursor = None;
            self.has_older = false;
        }
    }

    pub(super) fn retain_terminal_notices_since(&mut self, start: usize) {
        let terminal_notices = self
            .log
            .iter()
            .skip(start)
            .filter(|entry| {
                matches!(
                    entry,
                    HistoryEntry::InferenceError { .. } | HistoryEntry::CommandError { .. }
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        // This is a tail rewrite, not a history reset. In particular, a busy
        // optimistic dispatch can begin at index zero while the window still
        // has daemon-backed pages before `older_cursor`.
        self.log.truncate(start);
        self.extend(terminal_notices);
    }

    #[allow(dead_code)]
    pub(super) fn pop(&mut self) -> Option<HistoryEntry> {
        self.log.pop()
    }

    pub(super) fn get_mut(&mut self, idx: usize) -> Option<&mut HistoryEntry> {
        self.log.get_mut(idx)
    }

    pub(super) fn last_mut(&mut self) -> Option<&mut HistoryEntry> {
        self.log.last_mut()
    }

    pub(super) fn iter_mut(&mut self) -> std::slice::IterMut<'_, HistoryEntry> {
        self.log.iter_mut()
    }

    pub(super) fn take_dirty(&mut self) -> DirtyScan {
        self.log.take_dirty()
    }

    pub(super) fn trim_front_to_target(&mut self) -> bool {
        let max_before_trim = HISTORY_WINDOW_TARGET_ENTRIES + HISTORY_PAGE_ENTRIES;
        if self.log.len() <= max_before_trim {
            return false;
        }

        let remove_count = self.log.len() - HISTORY_WINDOW_TARGET_ENTRIES;
        let removed = self.log.drain_front(remove_count);
        self.has_older = true;
        self.older_cursor = self
            .oldest_resident_cursor()
            .or_else(|| removed.iter().rev().find_map(entry_cursor))
            .or(self.older_cursor);
        true
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn prepend_history_page(
        &mut self,
        entries: Vec<HistoryEntry>,
        older_cursor: Option<i64>,
        has_older: bool,
    ) -> bool {
        if entries.is_empty() {
            self.has_older = has_older;
            self.older_cursor = older_cursor;
            return true;
        }

        let Some(current_cursor) = self.older_cursor else {
            return false;
        };
        let Some(newest_page_cursor) = entries.iter().rev().find_map(entry_cursor).or(older_cursor)
        else {
            return false;
        };
        if newest_page_cursor >= current_cursor {
            return false;
        }

        self.log.prepend(entries);
        self.older_cursor = older_cursor;
        self.has_older = has_older;
        true
    }

    fn oldest_resident_cursor(&self) -> Option<i64> {
        self.log.iter().find_map(entry_cursor)
    }
}

impl App {
    pub(super) fn enforce_history_window(&mut self) -> bool {
        if !self.chat_pinned_to_tail {
            return false;
        }
        if !self.history.trim_front_to_target() {
            return false;
        }
        self.mark_chat_geometry_dirty_from(0);
        true
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn prepend_history_page(
        &mut self,
        entries: Vec<HistoryEntry>,
        older_cursor: Option<i64>,
        has_older: bool,
    ) -> bool {
        if !self
            .history
            .prepend_history_page(entries, older_cursor, has_older)
        {
            return false;
        }
        self.mark_chat_geometry_dirty_from(0);
        true
    }
}

fn entry_cursor(entry: &HistoryEntry) -> Option<i64> {
    match entry {
        HistoryEntry::User { seq, .. } | HistoryEntry::Agent { seq, .. } => *seq,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retain_terminal_notices_since_removes_only_optimistic_tail_rows() {
        let mut history = HistoryWindow::from(vec![HistoryEntry::Plain {
            line: "resident".to_string(),
        }]);
        let start = history.len();
        history.push(HistoryEntry::Plain {
            line: "optimistic".to_string(),
        });
        history.push(HistoryEntry::CommandError {
            line: "dispatch failed".to_string(),
        });
        history.push(HistoryEntry::InferenceError {
            summary: "provider failed".to_string(),
            detail: "detail".to_string(),
            expanded: false,
        });

        history.retain_terminal_notices_since(start);

        assert_eq!(history.len(), 3);
        assert!(matches!(&history[0], HistoryEntry::Plain { line } if line == "resident"));
        assert!(
            matches!(&history[1], HistoryEntry::CommandError { line } if line == "dispatch failed")
        );
        assert!(
            matches!(&history[2], HistoryEntry::InferenceError { summary, .. } if summary == "provider failed")
        );
    }

    #[test]
    fn retain_terminal_notices_since_preserves_pagination_at_zero() {
        let mut history = HistoryWindow::from_history_page(
            vec![HistoryEntry::CommandError {
                line: "dispatch failed".to_string(),
            }],
            Some(41),
            true,
        );

        history.retain_terminal_notices_since(0);

        assert_eq!(history.len(), 1);
        assert!(
            matches!(&history[0], HistoryEntry::CommandError { line } if line == "dispatch failed")
        );
        assert_eq!(history.older_cursor(), Some(41));
        assert!(history.has_older());
    }
}
