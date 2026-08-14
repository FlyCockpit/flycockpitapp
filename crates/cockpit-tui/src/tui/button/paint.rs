use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::ButtonSpec;

pub(crate) fn bracketed_label(label: &str) -> String {
    format!("[{label}]")
}

pub(crate) fn display_width(text: &str) -> u16 {
    UnicodeWidthStr::width(text) as u16
}

/// First `[label]` run in `text`: display-column offset of `[` and the
/// inner label (without brackets).
pub(crate) fn first_bracketed_label(text: &str) -> Option<(u16, String)> {
    let start = text.find('[')?;
    let rest = &text[start + '['.len_utf8()..];
    let end = rest.find(']')?;
    let inner = rest[..end].to_string();
    Some((display_width(&text[..start]), inner))
}

pub(crate) fn clip_to_display_width(text: &str, max: u16) -> String {
    if max == 0 {
        return String::new();
    }
    let max = usize::from(max);
    let mut out = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let w = ch.width().unwrap_or(0);
        if used.saturating_add(w) > max {
            break;
        }
        out.push(ch);
        used += w;
    }
    out
}

/// Paint `[label]` into `frame` at `(x, y)` clipped to `max_width` display cells.
/// Returns the exact painted rectangle, or `None` when nothing is visible.
pub(crate) fn paint_button(
    frame: &mut Frame<'_>,
    x: u16,
    y: u16,
    max_width: u16,
    spec: &ButtonSpec,
    style: Style,
) -> Option<Rect> {
    if max_width == 0 {
        return None;
    }
    let painted = clip_to_display_width(&bracketed_label(&spec.label), max_width);
    let width = display_width(&painted);
    if width == 0 {
        return None;
    }
    let area = frame.area();
    if y >= area.bottom() || x >= area.right() {
        return None;
    }
    let width = width.min(area.right().saturating_sub(x));
    if width == 0 {
        return None;
    }
    let painted = clip_to_display_width(&painted, width);
    let width = display_width(&painted);
    if width == 0 {
        return None;
    }
    let buf = frame.buffer_mut();
    let mut col = x;
    for ch in painted.chars() {
        let w = ch.width().unwrap_or(0) as u16;
        if w == 0 {
            continue;
        }
        if col >= area.right() {
            break;
        }
        if let Some(cell) = buf.cell_mut((col, y)) {
            cell.set_char(ch);
            cell.set_style(style);
        }
        col = col.saturating_add(w);
    }
    Some(Rect::new(x, y, width, 1))
}
