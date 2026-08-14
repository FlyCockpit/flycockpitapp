//! PTY screen snapshots and byte-exact terminal input helpers.
//!
//! SGR mouse encoding uses **one-based** wire coordinates:
//! `\x1b[<btn;x;yM` press and `\x1b[<btn;x;ym` release.
//! Left = 0, middle = 1, right = 2, motion = +32, wheel = 64/65/66/67.

use std::time::{Duration, Instant};

use super::osc52_observer::Osc52Observer;

/// Ready-composer marker rendered by the production TUI.
pub const COMPOSER_PLACEHOLDER: &str = "Message FlyCockpit — / commands · Ctrl+K keys · /setup";

/// Startup surfaces that must not appear once the hermetic recipe has run.
pub const UNWANTED_STARTUP_MARKERS: &[&str] = &[
    "Choose workspace trust:",
    "/model — pick the active model",
    "Configuration required",
    "Choose a provider",
];

/// One-based SGR wire coordinate pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellPos {
    /// Zero-based screen row.
    pub row: u16,
    /// Zero-based screen column.
    pub col: u16,
}

impl CellPos {
    /// One-based SGR X (column).
    pub fn sgr_x(self) -> u16 {
        self.col.saturating_add(1)
    }

    /// One-based SGR Y (row).
    pub fn sgr_y(self) -> u16 {
        self.row.saturating_add(1)
    }
}

/// Immutable snapshot of the current visible cell grid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScreenSnapshot {
    rows: u16,
    cols: u16,
    cells: Vec<SnapshotCell>,
    contents: String,
    composer_marker: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotCell {
    pub row: u16,
    pub col: u16,
    pub text: String,
    pub inverse: bool,
    /// Indexed SGR foreground, when the cell is not the default color.
    pub fg_index: Option<u8>,
    /// Indexed SGR background, when the cell is not the default color.
    pub bg_index: Option<u8>,
    pub fg_rgb: Option<(u8, u8, u8)>,
    pub bg_rgb: Option<(u8, u8, u8)>,
}

impl ScreenSnapshot {
    pub fn empty() -> Self {
        Self {
            rows: 0,
            cols: 0,
            cells: Vec::new(),
            contents: String::new(),
            composer_marker: false,
        }
    }

    pub fn from_screen(screen: &vt100::Screen) -> Self {
        let (rows, cols) = screen.size();
        let mut cells = Vec::with_capacity(usize::from(rows) * usize::from(cols));
        for row in 0..rows {
            for col in 0..cols {
                let (text, inverse, fg_index, bg_index, fg_rgb, bg_rgb) = match screen.cell(row, col)
                {
                    Some(cell) => (
                        cell.contents().to_string(),
                        cell.inverse(),
                        match cell.fgcolor() {
                            vt100::Color::Idx(idx) => Some(idx),
                            _ => None,
                        },
                        match cell.bgcolor() {
                            vt100::Color::Idx(idx) => Some(idx),
                            _ => None,
                        },
                        match cell.fgcolor() {
                            vt100::Color::Rgb(r, g, b) => Some((r, g, b)),
                            _ => None,
                        },
                        match cell.bgcolor() {
                            vt100::Color::Rgb(r, g, b) => Some((r, g, b)),
                            _ => None,
                        },
                    ),
                    None => (String::new(), false, None, None, None, None),
                };
                cells.push(SnapshotCell {
                    row,
                    col,
                    text,
                    inverse,
                    fg_index,
                    bg_index,
                    fg_rgb,
                    bg_rgb,
                });
            }
        }
        let contents = screen.contents();
        let composer_marker = contents.contains(COMPOSER_PLACEHOLDER);
        Self {
            rows,
            cols,
            cells,
            contents,
            composer_marker,
        }
    }

    pub fn size(&self) -> (u16, u16) {
        (self.rows, self.cols)
    }

    pub fn contents(&self) -> String {
        self.contents.clone()
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.contents.contains(needle)
    }

    pub fn composer_marker(&self) -> bool {
        self.composer_marker
    }

    pub fn cells(&self) -> &[SnapshotCell] {
        &self.cells
    }

    /// Visible grid plus composer-marker flag used by protocol no-op cases.
    pub fn visible_state(&self) -> (Vec<SnapshotCell>, bool) {
        (self.cells.clone(), self.composer_marker)
    }

    /// Concatenate a row's cell text, preserving empty cells as spaces.
    pub fn row_text(&self, row: u16) -> String {
        let mut out = String::new();
        for col in 0..self.cols {
            match self.cell_at(row, col) {
                Some(cell) if !cell.text.is_empty() => out.push_str(&cell.text),
                _ => out.push(' '),
            }
        }
        out
    }

    /// True when `needle` is contiguous on a single row.
    pub fn has_unwrapped_text(&self, needle: &str) -> bool {
        self.find_text(needle).is_some()
    }

    /// True when the child painted a box-drawing top border of `width` cells.
    pub fn has_box_top_width(&self, width: u16) -> bool {
        for row in 0..self.rows {
            let text = self.row_text(row);
            let trimmed = text.trim_end();
            if trimmed.starts_with('╭') && trimmed.ends_with('╮') {
                return unicode_width::UnicodeWidthStr::width(trimmed) == usize::from(width);
            }
        }
        false
    }

    pub fn find_text(&self, needle: &str) -> Option<CellPos> {
        self.find_text_span(needle).map(|(start, _)| start)
    }

    /// Inclusive start/end cells of a contiguous `needle` on one row.
    pub fn find_text_span(&self, needle: &str) -> Option<(CellPos, CellPos)> {
        if needle.is_empty() {
            return None;
        }
        let chars: Vec<char> = needle.chars().collect();
        let last = u16::try_from(chars.len().saturating_sub(1)).ok()?;
        for row in 0..self.rows {
            let mut col = 0u16;
            while col < self.cols {
                if self.row_matches(row, col, &chars) {
                    return Some((
                        CellPos { row, col },
                        CellPos {
                            row,
                            col: col.saturating_add(last),
                        },
                    ));
                }
                col = col.saturating_add(1);
            }
        }
        None
    }

    pub fn has_inverse(&self) -> bool {
        self.cells.iter().any(|cell| cell.inverse)
    }

    pub fn inverse_cells(&self) -> impl Iterator<Item = &SnapshotCell> {
        self.cells.iter().filter(|cell| cell.inverse)
    }

    /// First non-whitespace cell and last non-whitespace cell on `row`.
    pub fn row_content_span(&self, row: u16) -> Option<(CellPos, CellPos)> {
        let mut first = None;
        let mut last = None;
        for col in 0..self.cols {
            let Some(cell) = self.cell_at(row, col) else {
                continue;
            };
            if cell.text.chars().all(char::is_whitespace) {
                continue;
            }
            let pos = CellPos { row, col };
            if first.is_none() {
                first = Some(pos);
            }
            last = Some(pos);
        }
        Some((first?, last?))
    }

    fn row_matches(&self, row: u16, start_col: u16, needle: &[char]) -> bool {
        let mut col = start_col;
        for expected in needle {
            let Some(cell) = self.cell_at(row, col) else {
                return false;
            };
            let mut chars = cell.text.chars();
            let Some(got) = chars.next() else {
                return false;
            };
            if got != *expected || chars.next().is_some() {
                return false;
            }
            col = col.saturating_add(1);
        }
        true
    }

    fn cell_at(&self, row: u16, col: u16) -> Option<&SnapshotCell> {
        let width = usize::from(self.cols);
        let idx = usize::from(row) * width + usize::from(col);
        self.cells.get(idx)
    }
}

/// Encode an SGR mouse event. `x` and `y` are **one-based** wire coordinates.
pub fn sgr_mouse(button: u8, x: u16, y: u16, press: bool) -> Vec<u8> {
    let trailer = if press { b'M' } else { b'm' };
    format!("\x1b[<{button};{x};{y}{}", trailer as char).into_bytes()
}

pub fn sgr_left_down(x: u16, y: u16) -> Vec<u8> {
    sgr_mouse(0, x, y, true)
}

pub fn sgr_left_up(x: u16, y: u16) -> Vec<u8> {
    sgr_mouse(0, x, y, false)
}

/// Left press then release at one-based coordinates.
pub fn sgr_left_click(x: u16, y: u16) -> Vec<u8> {
    let mut out = sgr_left_down(x, y);
    out.extend_from_slice(&sgr_left_up(x, y));
    out
}

pub fn sgr_middle_click(x: u16, y: u16) -> Vec<u8> {
    let mut out = sgr_mouse(1, x, y, true);
    out.extend_from_slice(&sgr_mouse(1, x, y, false));
    out
}

pub fn sgr_right_click(x: u16, y: u16) -> Vec<u8> {
    let mut out = sgr_mouse(2, x, y, true);
    out.extend_from_slice(&sgr_mouse(2, x, y, false));
    out
}

/// Left-button drag / motion (`button + 32`).
pub fn sgr_left_drag(x: u16, y: u16) -> Vec<u8> {
    sgr_mouse(32, x, y, true)
}

/// Motion with no button (`35`).
pub fn sgr_motion(x: u16, y: u16) -> Vec<u8> {
    sgr_mouse(35, x, y, true)
}

pub fn sgr_wheel_up(x: u16, y: u16) -> Vec<u8> {
    sgr_mouse(64, x, y, true)
}

pub fn sgr_wheel_down(x: u16, y: u16) -> Vec<u8> {
    sgr_mouse(65, x, y, true)
}

pub fn sgr_wheel_left(x: u16, y: u16) -> Vec<u8> {
    sgr_mouse(66, x, y, true)
}

pub fn sgr_wheel_right(x: u16, y: u16) -> Vec<u8> {
    sgr_mouse(67, x, y, true)
}

/// Legacy X10 / non-SGR mouse sequence (not the primary encoding).
pub fn x10_mouse(button: u8, x: u16, y: u16) -> Vec<u8> {
    let cb = 32 + button;
    let cx = 32 + u8::try_from(x.min(223)).unwrap_or(223);
    let cy = 32 + u8::try_from(y.min(223)).unwrap_or(223);
    vec![0x1b, b'[', b'M', cb, cx, cy]
}

/// Complete but malformed SGR (wrong terminator).
pub fn sgr_malformed_complete(button: u8, x: u16, y: u16) -> Vec<u8> {
    format!("\x1b[<{button};{x};{y}Z").into_bytes()
}

pub fn bracketed_paste_start() -> Vec<u8> {
    b"\x1b[200~".to_vec()
}

pub fn bracketed_paste_end() -> Vec<u8> {
    b"\x1b[201~".to_vec()
}

/// Wrap `payload` in a complete bracketed-paste envelope.
pub fn bracketed_paste(payload: &str) -> Vec<u8> {
    let mut out = bracketed_paste_start();
    out.extend_from_slice(payload.as_bytes());
    out.extend_from_slice(&bracketed_paste_end());
    out
}

/// Fragment a bracketed paste into distinct writes (start / body / end).
pub fn fragmented_bracketed_paste(chunks: &[&str]) -> Vec<Vec<u8>> {
    let mut frames = vec![bracketed_paste_start()];
    for chunk in chunks {
        frames.push(chunk.as_bytes().to_vec());
    }
    frames.push(bracketed_paste_end());
    frames
}

pub fn wait_until_blocking(label: &str, timeout: Duration, mut probe: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(2);
    loop {
        if probe() {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {label}");
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

/// Keep the observer type in this module's public surface for dependents.
pub type PtyOsc52Observer = Osc52Observer;
