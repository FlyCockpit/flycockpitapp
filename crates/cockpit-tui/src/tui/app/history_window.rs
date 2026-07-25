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
