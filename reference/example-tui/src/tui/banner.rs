//! The new-chat splash: the P-51 Mustang pixel art from flycockpitapp,
//! copied verbatim (`p51-6-mirror.sh` / `cockpit-core::banner`).
//!
//! Each output row covers two input rows; each output column covers two
//! input columns. The four cells in a 2×2 group become one half-block
//! glyph plus an (fg, optional bg) pair. Result: 6 rows × 18 columns.

use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

/// Mirrored P-51 plane grid as 12 rows of 36 single-char cells, copied
/// verbatim from flycockpitapp. `.` = transparent; `a`–`h` key into
/// [`P51_PALETTE`].
const P51_PLANE: [&str; 12] = [
    "..........................hhhh......",
    ".hh.....................ddhhh.......",
    ".hhh..................eeeddd......h.",
    ".hhhh.ee...........cgggdeee.......d.",
    "hhhhhhhhhhhhhhhhhhccccccchhhhhhhh.e.",
    ".deeeehhhhhddddhhhhhhhhhhhhaaaaaeabf",
    "..........ddddeeeeeeeeeeeeedddddd.e.",
    "..............ddeeeeeeee..........d.",
    "............ddddddd...............h.",
    "..........hhhddd....................",
    ".........hhhhh......................",
    "....................................",
];

/// ANSI 256-color palette, indexed by `'a'..='h'` − `'a'`. Same values
/// as flycockpitapp's mirrored P-51 script.
const P51_PALETTE: [u8; 8] = [0, 3, 6, 7, 8, 11, 14, 15];

const PLANE_WIDTH: usize = 36;
const PLANE_HEIGHT: usize = 12;
/// Rendered banner width in terminal columns.
pub const RENDERED_WIDTH: usize = PLANE_WIDTH / 2;
/// Rendered banner height in terminal rows.
pub const RENDERED_HEIGHT: usize = PLANE_HEIGHT / 2;

/// The P-51 as ratatui lines, one span per 2×2 cell group. Callers
/// center the paragraph; this does not add indent.
pub fn p51_lines() -> Vec<Line<'static>> {
    resolve()
        .into_iter()
        .map(|row| Line::from(row.into_iter().map(cell_span).collect::<Vec<_>>()))
        .collect()
}

type ResolvedCell = Option<(&'static str, u8, Option<u8>)>;

fn resolve() -> Vec<Vec<ResolvedCell>> {
    let mut out = Vec::with_capacity(RENDERED_HEIGHT);
    for y in (0..PLANE_HEIGHT).step_by(2) {
        let top = P51_PLANE[y].as_bytes();
        let bot = P51_PLANE[y + 1].as_bytes();
        let mut row = Vec::with_capacity(RENDERED_WIDTH);
        for x in (0..PLANE_WIDTH).step_by(2) {
            row.push(cell_parts(
                top[x] as char,
                top[x + 1] as char,
                bot[x] as char,
                bot[x + 1] as char,
            ));
        }
        out.push(row);
    }
    out
}

fn cell_span(cell: ResolvedCell) -> Span<'static> {
    match cell {
        None => Span::raw(" "),
        Some((glyph, fg, Some(bg))) => Span::styled(
            glyph,
            Style::default()
                .fg(Color::Indexed(fg))
                .bg(Color::Indexed(bg)),
        ),
        Some((glyph, fg, None)) => Span::styled(glyph, Style::default().fg(Color::Indexed(fg))),
    }
}

/// Resolve one 2×2 group. Discovery order is the mirrored script's
/// (`ur`, `ul`, `lr`, `ll`). First distinct color is fg; the second,
/// if any, is bg. The four "is this cell the fg color?" bits pick a
/// half-block glyph.
fn cell_parts(ul: char, ur: char, ll: char, lr: char) -> ResolvedCell {
    let mut unique = [None; 4];
    let mut count = 0;
    for &c in &[ur, ul, lr, ll] {
        if c == '.' {
            continue;
        }
        if unique.iter().take(count).any(|x| *x == Some(c)) {
            continue;
        }
        unique[count] = Some(c);
        count += 1;
    }
    if count == 0 {
        return None;
    }
    let a = unique[0].expect("count >= 1");
    let bits = [ul == a, ur == a, ll == a, lr == a];
    Some((
        glyph_for_pattern(bits),
        color_for(a),
        unique[1].map(color_for),
    ))
}

fn color_for(c: char) -> u8 {
    let idx = (c as u8).wrapping_sub(b'a') as usize;
    *P51_PALETTE.get(idx).unwrap_or(&15)
}

fn glyph_for_pattern(bits: [bool; 4]) -> &'static str {
    match bits {
        [true, true, true, true] => "█",
        [true, true, true, false] => "▛",
        [true, true, false, true] => "▜",
        [true, false, true, true] => "▙",
        [false, true, true, true] => "▟",
        [true, true, false, false] => "▀",
        [false, false, true, true] => "▄",
        [true, false, true, false] => "▌",
        [false, true, false, true] => "▐",
        [true, false, false, true] => "▚",
        [false, true, true, false] => "▞",
        [true, false, false, false] => "▘",
        [false, true, false, false] => "▝",
        [false, false, true, false] => "▖",
        [false, false, false, true] => "▗",
        [false, false, false, false] => " ",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plane_matches_flycockpitapp_grid() {
        assert_eq!(P51_PLANE.len(), PLANE_HEIGHT);
        assert_eq!(P51_PALETTE, [0, 3, 6, 7, 8, 11, 14, 15]);
        assert_eq!(P51_PLANE[0], "..........................hhhh......");
        assert_eq!(P51_PLANE[10], ".........hhhhh......................");
        for (i, row) in P51_PLANE.iter().enumerate() {
            assert_eq!(row.chars().count(), PLANE_WIDTH, "row {i}");
        }
    }

    #[test]
    fn renders_six_by_eighteen() {
        let lines = p51_lines();
        assert_eq!(lines.len(), RENDERED_HEIGHT);
        for line in &lines {
            assert_eq!(line.width(), RENDERED_WIDTH);
        }
    }

    #[test]
    fn a_full_block_is_solid() {
        assert_eq!(glyph_for_pattern([true, true, true, true]), "█");
    }
}
