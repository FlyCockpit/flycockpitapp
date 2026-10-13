//! Exact multi-literal matcher behind every [`RedactionTable`].
//!
//! One Aho-Corasick automaton (`Standard`, contiguous NFA) indexes an
//! *anchor* per entry: the entry's whole value when it is at most
//! [`ANCHOR_LEN`] bytes, otherwise its first [`ANCHOR_LEN`] bytes. Every
//! anchor hit is confirmed against the entries sharing that anchor by a direct
//! comparison of the haystack with the entry's full value, so the reported
//! occurrences are exactly the occurrences of the registered values:
//!
//! - **Complete**: an occurrence of value `v` at `s` contains the occurrence
//!   of its anchor `v[..min(len, ANCHOR_LEN)]` at `s`, and overlapping
//!   `Standard` search reports every occurrence of every anchor; the
//!   confirmation of `v` at `s` then succeeds.
//! - **Sound**: an occurrence is reported only after `haystack[s..s+len]`
//!   equals the entry's value byte-for-byte.
//! - **Unique**: each entry sits in exactly one anchor's candidate list, and
//!   each anchor occurrence is reported once, so each `(start, entry)` is
//!   reported once.
//!
//! The matcher therefore enumerates the same `(start, end, entry)` set as a
//! `Standard` overlapping search over the full values, and the
//! leftmost-longest non-overlapping sequence derived from that set is the one
//! a `LeftmostLongest` automaton over the full values emits. What changes is
//! size: a long literal (a private key, its lines, and their encodings)
//! costs at most [`ANCHOR_LEN`] automaton states instead of one state per
//! byte, and one automaton replaces the former lookup/overlap pair. Values
//! are not copied: confirmation reads them from the table's entry vector,
//! which is aligned 1:1 with the index this matcher was built from.

use std::collections::HashMap;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickKind, MatchKind};
use anyhow::Result;

use super::RedactionEntry;

/// Longest anchor registered in the automaton. Values up to this length are
/// matched whole by the automaton; longer values are confirmed by comparison.
pub(super) const ANCHOR_LEN: usize = 32;

/// One confirmed occurrence of an entry's value: `[start, end)` in the
/// haystack and the index of the entry in the table's entry vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct LiteralMatch {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) entry: usize,
}

/// Cheap to clone: the compiled index is shared behind an `Arc`, so the
/// `union`/`enforced`/`with_sealed_replacements` views never copy it.
#[derive(Clone)]
pub(super) struct LiteralMatcher {
    inner: Arc<Index>,
}

struct Index {
    /// `Standard` automaton over the distinct anchors.
    anchors: AhoCorasick,
    /// Candidate entries of anchor `a`: `candidates[offsets[a]..offsets[a + 1]]`.
    offsets: Vec<u32>,
    candidates: Vec<u32>,
    /// Entry count the index was built for; every query asserts alignment.
    entry_count: usize,
}

impl LiteralMatcher {
    /// Build the index for `entries` (non-empty, every value at least
    /// [`super::MIN_REDACTION_ENTRY_LENGTH`] bytes).
    pub(super) fn build(entries: &[RedactionEntry]) -> Result<Self> {
        Self::build_with_anchor_len(entries, ANCHOR_LEN)
    }

    pub(super) fn build_with_anchor_len(
        entries: &[RedactionEntry],
        anchor_len: usize,
    ) -> Result<Self> {
        assert!(
            anchor_len >= super::MIN_REDACTION_ENTRY_LENGTH,
            "an anchor never truncates a minimum-length literal"
        );
        let entry_count = u32::try_from(entries.len())
            .map_err(|_| anyhow::anyhow!("too many redaction entries for one matcher"))?;
        let mut anchor_ids: HashMap<&[u8], usize> = HashMap::new();
        let mut anchors: Vec<&[u8]> = Vec::new();
        let mut members: Vec<Vec<u32>> = Vec::new();
        for (index, entry) in (0..entry_count).zip(entries) {
            let bytes = entry.value.as_bytes();
            let anchor = &bytes[..bytes.len().min(anchor_len)];
            let id = *anchor_ids.entry(anchor).or_insert_with(|| {
                anchors.push(anchor);
                members.push(Vec::new());
                anchors.len() - 1
            });
            members[id].push(index);
        }
        let mut offsets = Vec::with_capacity(members.len() + 1);
        let mut candidates = Vec::with_capacity(entries.len());
        offsets.push(0);
        for list in &members {
            candidates.extend_from_slice(list);
            offsets.push(
                u32::try_from(candidates.len())
                    .map_err(|_| anyhow::anyhow!("too many redaction entries for one matcher"))?,
            );
        }
        // The contiguous NFA is the compact representation: the library's
        // automatic choice would pick a DFA for small anchor counts, whose
        // dense tables are far larger than this per-generation artifact
        // should be. `Standard` is the only kind with overlapping search.
        let anchors = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::ContiguousNFA))
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(false)
            .build(&anchors)
            .map_err(|e| anyhow::anyhow!("building aho-corasick: {e}"))?;
        Ok(Self {
            inner: Arc::new(Index {
                anchors,
                offsets,
                candidates,
                entry_count: entries.len(),
            }),
        })
    }

    /// Visit every occurrence of every entry value in `haystack`, overlapping
    /// and self-overlapping included, in automaton order. Returning `false`
    /// from `visit` stops the scan.
    fn scan(
        &self,
        entries: &[RedactionEntry],
        haystack: &str,
        mut visit: impl FnMut(LiteralMatch) -> bool,
    ) {
        let index = &*self.inner;
        assert_eq!(
            entries.len(),
            index.entry_count,
            "redaction matcher is aligned 1:1 with its table's entries"
        );
        let bytes = haystack.as_bytes();
        for hit in index.anchors.find_overlapping_iter(haystack) {
            let anchor = hit.pattern().as_usize();
            let start = hit.start();
            let range = index.offsets[anchor] as usize..index.offsets[anchor + 1] as usize;
            for &entry in &index.candidates[range] {
                let entry = entry as usize;
                let value = entries[entry].value.as_bytes();
                let end = start + value.len();
                if bytes.get(start..end) == Some(value)
                    && !visit(LiteralMatch { start, end, entry })
                {
                    return;
                }
            }
        }
    }

    /// Whether any entry value occurs in `haystack`. Production gates on an
    /// empty [`Self::overlapping`] result; the differential tests pin this
    /// early-exit form against the reference automata.
    #[cfg(test)]
    pub(super) fn is_match(&self, entries: &[RedactionEntry], haystack: &str) -> bool {
        let mut found = false;
        self.scan(entries, haystack, |_| {
            found = true;
            false
        });
        found
    }

    /// Every occurrence of every entry value, overlapping included, sorted by
    /// `(start, end)`. Distinct entries have distinct values, so no two
    /// occurrences share both bounds.
    pub(super) fn overlapping(
        &self,
        entries: &[RedactionEntry],
        haystack: &str,
    ) -> Vec<LiteralMatch> {
        let mut out = Vec::new();
        self.scan(entries, haystack, |found| {
            out.push(found);
            true
        });
        out.sort_unstable();
        out
    }

    /// The non-overlapping leftmost-longest sequence: the earliest-starting
    /// occurrence (the longest among those starting there), then the same
    /// choice among occurrences starting at or after its end, and so on.
    pub(super) fn leftmost_longest(
        &self,
        entries: &[RedactionEntry],
        haystack: &str,
    ) -> Vec<LiteralMatch> {
        let mut all = self.overlapping(entries, haystack);
        all.sort_unstable_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        let mut out = Vec::new();
        let mut resume = 0usize;
        for found in all {
            if found.start >= resume {
                resume = found.end;
                out.push(found);
            }
        }
        out
    }

    /// Heap owned by the compiled index: the automaton's library-reported
    /// usage plus the anchor candidate lists.
    pub(super) fn memory_usage(&self) -> usize {
        let index = &*self.inner;
        std::mem::size_of::<Index>()
            .saturating_add(index.anchors.memory_usage())
            .saturating_add(index.offsets.capacity().saturating_mul(4))
            .saturating_add(index.candidates.capacity().saturating_mul(4))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::OrdinarySource;

    /// Deterministic xorshift so every failure replays from its seed.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }
    }

    fn random_literal(rng: &mut Rng, alphabet: &[char], min: usize, max: usize) -> String {
        let len = min + rng.below(max - min + 1);
        let mut out = String::new();
        while out.len() < len {
            out.push(alphabet[rng.below(alphabet.len())]);
        }
        out
    }

    /// Entries in production order: longest first, then by value, deduped.
    fn entries(mut values: Vec<String>) -> Vec<RedactionEntry> {
        values.retain(|value| value.len() >= crate::redact::MIN_REDACTION_ENTRY_LENGTH);
        values.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        values.dedup();
        values
            .into_iter()
            .map(|value| {
                RedactionEntry::ordinary(value, "$denylist".into(), OrdinarySource::Credential)
            })
            .collect()
    }

    /// A haystack dense in whole literals, overlapping literals, prefixes
    /// (anchor hits that must not confirm), and near misses.
    fn haystack(rng: &mut Rng, entries: &[RedactionEntry], alphabet: &[char]) -> String {
        let mut out = String::new();
        for _ in 0..(1 + rng.below(12)) {
            let value = entries[rng.below(entries.len())].value.as_str();
            let chars: Vec<char> = value.chars().collect();
            match rng.below(5) {
                0 => out.push_str(value),
                1 => out.extend(&chars[..rng.below(chars.len())]),
                2 => {
                    out.extend(&chars[..chars.len() - 1]);
                    out.push(alphabet[rng.below(alphabet.len())]);
                }
                3 => out.extend(&chars[rng.below(chars.len())..]),
                _ => out.push_str(&random_literal(rng, alphabet, 1, 8)),
            }
        }
        out
    }

    fn reference(entries: &[RedactionEntry], kind: MatchKind) -> AhoCorasick {
        AhoCorasick::builder()
            .match_kind(kind)
            .build(entries.iter().map(|entry| entry.value.as_str()))
            .expect("reference automaton")
    }

    /// The anchor index reports exactly what full-literal automata report:
    /// the `Standard` overlapping set, the `LeftmostLongest` sequence, and
    /// `is_match`, across anchor lengths that cut inside literals and inside
    /// multi-byte characters.
    #[test]
    fn anchor_index_matches_full_literal_automata() {
        let alphabets: [&[char]; 3] = [&['a', 'b'], &['a', 'b', 'c'], &['a', 'é', 'b']];
        for seed in 1..=600u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let alphabet = alphabets[seed as usize % alphabets.len()];
            let max_len = [12, 48, 160][seed as usize % 3];
            let count = 1 + rng.below(24);
            let values = (0..count)
                .map(|_| random_literal(&mut rng, alphabet, 4, max_len))
                .collect();
            let entries = entries(values);
            let anchor_len = [4, 5, 7, 16, ANCHOR_LEN][seed as usize % 5];
            let matcher = LiteralMatcher::build_with_anchor_len(&entries, anchor_len).unwrap();
            let standard = reference(&entries, MatchKind::Standard);
            let leftmost = reference(&entries, MatchKind::LeftmostLongest);
            for _ in 0..8 {
                let body = haystack(&mut rng, &entries, alphabet);
                let mut expected: Vec<LiteralMatch> = standard
                    .find_overlapping_iter(&body)
                    .map(|m| LiteralMatch {
                        start: m.start(),
                        end: m.end(),
                        entry: m.pattern().as_usize(),
                    })
                    .collect();
                expected.sort_unstable();
                assert_eq!(
                    matcher.overlapping(&entries, &body),
                    expected,
                    "overlapping set, seed {seed}"
                );
                let expected: Vec<LiteralMatch> = leftmost
                    .find_iter(&body)
                    .map(|m| LiteralMatch {
                        start: m.start(),
                        end: m.end(),
                        entry: m.pattern().as_usize(),
                    })
                    .collect();
                assert_eq!(
                    matcher.leftmost_longest(&entries, &body),
                    expected,
                    "leftmost-longest sequence, seed {seed}"
                );
                assert_eq!(
                    matcher.is_match(&entries, &body),
                    standard.is_match(&body),
                    "is_match, seed {seed}"
                );
            }
        }
    }

    /// Literals sharing one anchor (a key and its own first line; many keys
    /// behind one armor header) are each confirmed independently.
    #[test]
    fn literals_sharing_an_anchor_confirm_independently() {
        let header = "-----BEGIN TEST-ONLY KEY MATERIAL-----";
        let first = format!("{header}\nfirst-key-body-0123456789");
        let second = format!("{header}\nsecond-key-body-9876543210");
        let entries = entries(vec![header.into(), first.clone(), second.clone()]);
        let matcher = LiteralMatcher::build(&entries).unwrap();
        let found = matcher.overlapping(&entries, &format!("x{second}y{header}z"));
        let values: Vec<&str> = found
            .iter()
            .map(|m| entries[m.entry].value.as_str())
            .collect();
        // Sorted by (start, end): the header inside `second` ends first.
        assert_eq!(values, [header, second.as_str(), header]);
        assert!(!matcher.is_match(
            &entries,
            &format!("{header}\nfirst-key-body-012345678")[1..]
        ));
        assert!(matcher.is_match(&entries, &first));
    }
}
