//! P-51 source art from `cockpit-core::banner` (`p51-6-mirror.sh`).
//!
//! Rendered the same way as a new Cockpit session: each terminal cell is a
//! 2×2 source group packed into a half-block glyph, so source pixels stay
//! square. Result is 18×6, matching `RENDERED_WIDTH` × `RENDERED_HEIGHT`.
//!
//! The isolated pixels on the right of the nose are the propeller disk.
//! Phases hide the top (and bottom) of that disk so the prop reads as
//! spinning. Nothing is drawn in front of the spinner — a white blade past
//! the nose was a smear, not a propeller.

/// Mirrored P-51, flying right. `.` is transparent; `a`–`h` index [`PALETTE`].
pub const P51: [&str; 12] = [
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

/// ANSI 256-color palette, indexed by `'a'..='h'` − `'a'`.
pub const PALETTE: [u8; 8] = [0, 3, 6, 7, 8, 11, 14, 15];

pub const SRC_WIDTH: usize = 36;
pub const SRC_HEIGHT: usize = 12;
pub const RENDERED_WIDTH: u16 = (SRC_WIDTH / 2) as u16;
pub const RENDERED_HEIGHT: u16 = (SRC_HEIGHT / 2) as u16;

const PROP_TOP: [(usize, usize); 2] = [(34, 2), (34, 3)];
const PROP_BOTTOM: [(usize, usize); 2] = [(34, 7), (34, 8)];

/// One revolution is four phases. 200ms each keeps the spin readable.
pub const PHASE_MS: u64 = 200;
pub const PHASE_COUNT: u64 = 4;

pub type Cell = Option<(&'static str, u8, Option<u8>)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropPhase(pub u8);

impl PropPhase {
    pub fn from_elapsed_ms(elapsed_ms: u64) -> Self {
        Self((elapsed_ms / PHASE_MS % PHASE_COUNT) as u8)
    }

    pub fn top_visible(self) -> bool {
        matches!(self.0, 0 | 3)
    }

    pub fn bottom_visible(self) -> bool {
        matches!(self.0, 0 | 1)
    }
}

/// Source grid with propeller phase applied. Rows stay [`SRC_WIDTH`] chars —
/// the art never grows past the spinner.
pub fn grid(phase: PropPhase) -> [String; SRC_HEIGHT] {
    let mut rows: [String; SRC_HEIGHT] = std::array::from_fn(|i| String::from(P51[i]));
    set_pixels(&mut rows, &PROP_TOP, phase.top_visible());
    set_pixels(&mut rows, &PROP_BOTTOM, phase.bottom_visible());
    rows
}

/// Half-block cells, identical packing to `cockpit_core::banner::active_cells`.
pub fn cells(phase: PropPhase) -> Vec<Vec<Cell>> {
    let rows = grid(phase);
    let mut out = Vec::with_capacity(RENDERED_HEIGHT as usize);
    for y in (0..SRC_HEIGHT).step_by(2) {
        let top = rows[y].as_bytes();
        let bot = rows[y + 1].as_bytes();
        let mut row = Vec::with_capacity(RENDERED_WIDTH as usize);
        for x in (0..SRC_WIDTH).step_by(2) {
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

pub fn rendered_size() -> (u16, u16) {
    (RENDERED_WIDTH, RENDERED_HEIGHT)
}

fn set_pixels(rows: &mut [String; SRC_HEIGHT], pixels: &[(usize, usize)], on: bool) {
    for &(x, y) in pixels {
        if on {
            put(rows, x, y, P51[y].as_bytes()[x] as char);
        } else {
            put(rows, x, y, '.');
        }
    }
}

fn put(rows: &mut [String; SRC_HEIGHT], x: usize, y: usize, ch: char) {
    let row = &mut rows[y];
    row.replace_range(x..x + 1, &ch.to_string());
}

fn color_for(ch: char) -> u8 {
    let idx = (ch as u8).wrapping_sub(b'a') as usize;
    *PALETTE.get(idx).unwrap_or(&15)
}

/// Mirrored P-51 discovery order: `ur`, `ul`, `lr`, `ll`.
fn cell_parts(ul: char, ur: char, ll: char, lr: char) -> Cell {
    let mut unique = [None; 4];
    let mut count = 0;
    for c in [ur, ul, lr, ll] {
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
    fn source_rows_are_uniform() {
        for (i, row) in P51.iter().enumerate() {
            assert_eq!(row.len(), SRC_WIDTH, "row {i}");
        }
    }

    #[test]
    fn matches_cockpit_banner_size() {
        assert_eq!(rendered_size(), (18, 6));
        let cells = cells(PropPhase(0));
        assert_eq!(cells.len(), 6);
        assert!(cells.iter().all(|row| row.len() == 18));
    }

    #[test]
    fn vertical_phase_keeps_the_prop_tops() {
        let rows = grid(PropPhase(0));
        assert_eq!(rows[2].as_bytes()[34], b'h');
        assert_eq!(rows[3].as_bytes()[34], b'd');
        assert_eq!(rows[7].as_bytes()[34], b'd');
        assert_eq!(rows[8].as_bytes()[34], b'h');
        assert_eq!(rows[2].len(), SRC_WIDTH);
    }

    #[test]
    fn tops_disappear_and_nothing_is_drawn_past_the_nose() {
        let rows = grid(PropPhase(2));
        assert_eq!(rows[2].as_bytes()[34], b'.');
        assert_eq!(rows[3].as_bytes()[34], b'.');
        assert_eq!(rows[7].as_bytes()[34], b'.');
        assert_eq!(rows[8].as_bytes()[34], b'.');
        for row in &rows {
            assert_eq!(row.len(), SRC_WIDTH, "prop must not grow past the spinner");
        }
        let spinner = &rows[5];
        assert_eq!(
            spinner.as_bytes()[SRC_WIDTH - 1],
            P51[5].as_bytes()[SRC_WIDTH - 1],
            "nose column stays the original spinner, not a white blade"
        );
    }

    #[test]
    fn phase_cycles_every_800ms() {
        assert_eq!(PropPhase::from_elapsed_ms(0).0, 0);
        assert_eq!(PropPhase::from_elapsed_ms(199).0, 0);
        assert_eq!(PropPhase::from_elapsed_ms(200).0, 1);
        assert_eq!(PropPhase::from_elapsed_ms(600).0, 3);
        assert_eq!(PropPhase::from_elapsed_ms(800).0, 0);
    }
}
