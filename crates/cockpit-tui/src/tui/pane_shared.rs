//! Small pure helpers shared by the `/sessions`, `/plans`, and `/stats`
//! panes. Hoisted here so the three panes keep one copy each rather than
//! drifting independently.

use std::path::Path;

/// Resolve a `project_id` the same way session creation and the CLI mirror do
/// (GOALS §15b): prefer the git worktree root for stability, else the cwd.
/// `worktree_root` is the daemon-resolved git root (git authority stays out of
/// the TUI); it is `None` when the cwd is not in a repo or has not been
/// resolved yet, in which case we fall back to `cwd`.
pub(crate) fn resolve_project_id(worktree_root: Option<&Path>, cwd: &Path) -> Option<String> {
    let root = worktree_root.unwrap_or(cwd);
    cockpit_core::session::project_id_for(root).ok()
}

/// Short prefix of a `project_id` hash for the title chip — the full
/// hash is long and the title only needs to be recognizable.
pub(crate) fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

/// Clamp a scroll offset so the selected rendered row span stays visible.
///
/// `selected_end` is exclusive. If the selected item is taller than the
/// viewport, keep its top row visible; otherwise keep the full span visible
/// whenever possible.
pub(crate) fn clamp_scroll_to_visible_span(
    scroll: usize,
    viewport_rows: usize,
    content_rows: usize,
    selected_start: usize,
    selected_end: usize,
) -> usize {
    let max_scroll = content_rows.saturating_sub(viewport_rows);
    let scroll = scroll.min(max_scroll);
    if viewport_rows == 0 || selected_start >= selected_end {
        return scroll;
    }

    let selected_rows = selected_end - selected_start;
    if selected_rows > viewport_rows {
        return selected_start.min(max_scroll);
    }

    if selected_start < scroll {
        selected_start
    } else if selected_end > scroll + viewport_rows {
        selected_end.saturating_sub(viewport_rows).min(max_scroll)
    } else {
        scroll
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_scroll_keeps_full_span_visible_when_it_fits() {
        assert_eq!(clamp_scroll_to_visible_span(0, 5, 20, 7, 10), 5);
        assert_eq!(clamp_scroll_to_visible_span(8, 5, 20, 2, 5), 2);
        assert_eq!(clamp_scroll_to_visible_span(4, 5, 20, 5, 8), 4);
    }

    #[test]
    fn clamp_scroll_keeps_top_visible_when_span_is_taller_than_viewport() {
        assert_eq!(clamp_scroll_to_visible_span(0, 3, 20, 6, 12), 6);
    }

    #[test]
    fn clamp_scroll_stays_within_content_bounds() {
        assert_eq!(clamp_scroll_to_visible_span(99, 5, 12, 10, 12), 7);
        assert_eq!(clamp_scroll_to_visible_span(0, 20, 12, 10, 12), 0);
    }
}
