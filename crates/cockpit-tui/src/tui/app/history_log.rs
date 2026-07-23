use std::ops::{Deref, Index, IndexMut};

use crate::tui::history::HistoryEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HistoryEntryId(u64);

#[derive(Debug, Clone)]
pub struct HistoryLog {
    entries: Vec<HistoryEntry>,
    ids: Vec<HistoryEntryId>,
    next_id: u64,
}

impl Default for HistoryLog {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            ids: Vec::new(),
            next_id: 1,
        }
    }
}

impl From<Vec<HistoryEntry>> for HistoryLog {
    fn from(entries: Vec<HistoryEntry>) -> Self {
        let mut log = Self::default();
        log.extend(entries);
        log
    }
}

impl Deref for HistoryLog {
    type Target = [HistoryEntry];

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl Index<usize> for HistoryLog {
    type Output = HistoryEntry;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

impl IndexMut<usize> for HistoryLog {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.entries[index]
    }
}

impl<'a> IntoIterator for &'a HistoryLog {
    type Item = &'a HistoryEntry;
    type IntoIter = std::slice::Iter<'a, HistoryEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl HistoryLog {
    pub(super) fn push(&mut self, entry: HistoryEntry) {
        let id = self.issue_id();
        self.entries.push(entry);
        self.ids.push(id);
        self.debug_assert_invariants();
    }

    pub(super) fn insert(&mut self, idx: usize, entry: HistoryEntry) {
        let id = self.issue_id();
        self.entries.insert(idx, entry);
        self.ids.insert(idx, id);
        self.debug_assert_invariants();
    }

    pub(super) fn remove(&mut self, idx: usize) -> HistoryEntry {
        self.ids.remove(idx);
        let entry = self.entries.remove(idx);
        self.debug_assert_invariants();
        entry
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.ids.clear();
        self.debug_assert_invariants();
    }

    pub(super) fn extend<I: IntoIterator<Item = HistoryEntry>>(&mut self, entries: I) {
        for entry in entries {
            self.push(entry);
        }
    }

    #[allow(dead_code)]
    pub(super) fn truncate(&mut self, len: usize) {
        self.entries.truncate(len);
        self.ids.truncate(len);
        self.debug_assert_invariants();
    }

    #[allow(dead_code)]
    pub(super) fn pop(&mut self) -> Option<HistoryEntry> {
        let entry = self.entries.pop();
        if entry.is_some() {
            self.ids.pop();
        }
        self.debug_assert_invariants();
        entry
    }

    pub(super) fn get_mut(&mut self, idx: usize) -> Option<&mut HistoryEntry> {
        self.entries.get_mut(idx)
    }

    pub(super) fn last_mut(&mut self) -> Option<&mut HistoryEntry> {
        self.entries.last_mut()
    }

    pub(super) fn iter_mut(&mut self) -> std::slice::IterMut<'_, HistoryEntry> {
        self.entries.iter_mut()
    }

    pub(super) fn id_at(&self, idx: usize) -> Option<HistoryEntryId> {
        self.ids.get(idx).copied()
    }

    pub(super) fn ids(&self) -> &[HistoryEntryId] {
        &self.ids
    }

    fn issue_id(&mut self) -> HistoryEntryId {
        let id = HistoryEntryId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        if self.next_id == 0 {
            self.next_id = 1;
        }
        id
    }

    fn debug_assert_invariants(&self) {
        debug_assert_eq!(self.entries.len(), self.ids.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(label: &str) -> HistoryEntry {
        HistoryEntry::Plain {
            line: label.to_string(),
        }
    }

    #[test]
    fn history_log_ids_are_stable_across_insert_and_remove() {
        let mut log = HistoryLog::default();
        for idx in 0..5 {
            log.push(entry(&format!("entry {idx}")));
        }
        let original_ids = log.ids().to_vec();

        log.insert(2, entry("inserted"));
        log.remove(0);

        assert_eq!(log.id_at(0), Some(original_ids[1]));
        assert_eq!(log.id_at(2), Some(original_ids[2]));
        assert_eq!(log.id_at(3), Some(original_ids[3]));
        assert_eq!(log.id_at(4), Some(original_ids[4]));
    }

    #[test]
    fn history_log_ids_are_never_reused() {
        let mut log = HistoryLog::default();
        log.push(entry("first"));
        let removed = log.id_at(0).unwrap();
        log.remove(0);

        log.push(entry("second"));
        assert_ne!(log.id_at(0), Some(removed));

        let before_clear = log.id_at(0).unwrap();
        log.clear();
        log.push(entry("third"));
        assert_ne!(log.id_at(0), Some(before_clear));
    }

    #[test]
    fn history_log_len_and_ids_stay_in_lockstep() {
        let mut log = HistoryLog::default();
        assert_eq!(log.len(), log.ids().len());

        log.push(entry("a"));
        assert_eq!(log.len(), log.ids().len());

        log.insert(0, entry("b"));
        assert_eq!(log.len(), log.ids().len());

        log.remove(1);
        assert_eq!(log.len(), log.ids().len());

        log.extend(vec![entry("c"), entry("d")]);
        assert_eq!(log.len(), log.ids().len());

        log.truncate(2);
        assert_eq!(log.len(), log.ids().len());

        log.pop();
        assert_eq!(log.len(), log.ids().len());

        log.clear();
        assert_eq!(log.len(), log.ids().len());
    }
}
