#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InnerScrollWindow {
    pub offset: usize,
    pub max_offset: usize,
    pub end: usize,
    pub more_above: usize,
    pub more_below: usize,
}

pub fn inner_scroll_window(
    total_rows: usize,
    visible_rows: usize,
    offset: usize,
) -> InnerScrollWindow {
    let visible_rows = visible_rows.max(1);
    let max_offset = total_rows.saturating_sub(visible_rows);
    let offset = offset.min(max_offset);
    let end = total_rows.min(offset.saturating_add(visible_rows));
    InnerScrollWindow {
        offset,
        max_offset,
        end,
        more_above: offset,
        more_below: total_rows.saturating_sub(end),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ToolResultScrollRegion {
    pub call_index: usize,
    pub row_start: usize,
    pub row_end: usize,
    pub offset: usize,
    pub max_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReasoningScrollRegion {
    pub row_start: usize,
    pub row_end: usize,
    pub offset: usize,
    pub max_offset: usize,
}
