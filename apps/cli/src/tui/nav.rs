//! Shared list-navigation index math.
//!
//! Every up/down-navigable selectable list in the TUI wraps at its ends:
//! pressing Up on the first item lands on the last, and Down on the last
//! lands on the first (GOALS §1a UX consistency). The one exception is
//! composer history recall, which clamps — it is not a list and lives
//! outside this module.
//!
//! Both helpers guard `len == 0` (returns 0 — caller renders nothing) and
//! a single-item list (stays on that item), so callers never index out of
//! bounds.

/// Index after a Down/`j` press in a `len`-item list, wrapping the last
/// item back to the first. `len == 0` returns 0.
pub fn wrap_next(i: usize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    if i + 1 >= len { 0 } else { i + 1 }
}

/// Index after an Up/`k` press in a `len`-item list, wrapping the first
/// item back to the last. `len == 0` returns 0.
pub fn wrap_prev(i: usize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    if i == 0 { len - 1 } else { i - 1 }
}

/// Recompute a scroll-window top offset so `selected` stays visible with
/// a one-row margin (scrolloff=1) above and below, except at the true ends
/// of the list. Hard stops, no wrap.
pub(crate) fn windowed_scroll(
    selected: usize,
    mut offset: usize,
    len: usize,
    window: usize,
) -> usize {
    if len <= window {
        return 0;
    }
    const SCROLLOFF: usize = 1;
    if selected < offset + SCROLLOFF {
        offset = selected.saturating_sub(SCROLLOFF);
    }
    if selected + SCROLLOFF + 1 > offset + window {
        offset = (selected + SCROLLOFF + 1).saturating_sub(window);
    }
    offset.min(len - window)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_stays_at_zero() {
        assert_eq!(wrap_next(0, 0), 0);
        assert_eq!(wrap_prev(0, 0), 0);
    }

    #[test]
    fn single_item_list_stays_put() {
        assert_eq!(wrap_next(0, 1), 0);
        assert_eq!(wrap_prev(0, 1), 0);
    }

    #[test]
    fn down_from_last_wraps_to_first() {
        assert_eq!(wrap_next(2, 3), 0);
    }

    #[test]
    fn up_from_first_wraps_to_last() {
        assert_eq!(wrap_prev(0, 3), 2);
    }

    #[test]
    fn interior_moves_are_plain_steps() {
        assert_eq!(wrap_next(0, 3), 1);
        assert_eq!(wrap_next(1, 3), 2);
        assert_eq!(wrap_prev(2, 3), 1);
        assert_eq!(wrap_prev(1, 3), 0);
    }

    /// A stored index that has drifted past the end (list shrank between a
    /// keypress and the next render) still wraps to a valid index rather
    /// than panicking or returning an out-of-bounds value.
    #[test]
    fn out_of_range_index_wraps_safely() {
        assert_eq!(wrap_next(9, 3), 0);
        assert_eq!(wrap_prev(9, 3), 8);
    }

    #[test]
    fn windowed_scroll_noops_when_everything_fits() {
        const W: usize = 5;
        assert_eq!(windowed_scroll(0, 0, 5, W), 0);
        assert_eq!(windowed_scroll(4, 0, 5, W), 0);
    }

    #[test]
    fn windowed_scroll_keeps_top_edge_pinned() {
        const W: usize = 5;
        assert_eq!(windowed_scroll(0, 0, 10, W), 0);
        assert_eq!(windowed_scroll(1, 0, 10, W), 0);
    }

    #[test]
    fn windowed_scroll_moves_down_with_margin() {
        const W: usize = 5;
        assert_eq!(windowed_scroll(5, 0, 10, W), 2);
    }

    #[test]
    fn windowed_scroll_clamps_at_bottom() {
        const W: usize = 5;
        assert_eq!(windowed_scroll(9, 4, 10, W), 5);
    }

    #[test]
    fn windowed_scroll_moves_up_with_margin() {
        const W: usize = 5;
        assert_eq!(windowed_scroll(4, 4, 10, W), 3);
    }
}
