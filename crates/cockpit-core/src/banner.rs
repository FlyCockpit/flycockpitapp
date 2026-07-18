//! Startup pixel banner (GOALS §1g).
//!
//! Renders a small P-51 Mustang in 256-color ANSI half-blocks. The
//! default P-51 source data comes from the mirrored shell script
//! `p51-6-mirror.sh` in the repo root; this module is the Rust port.
//! A parallel rooster (`rooster-6.sh`) ships alongside it; when a truthy
//! `COCKPIT_ROOSTER` env var is present the rooster renders *instead
//! of* the P-51 (`implementation notes` §9b).
//!
//! Each output row covers two input rows; each output column covers
//! two input columns. The four cells inside one 2×2 group decide one
//! half-block glyph + (fg, bg) pair via the same logic the shell
//! script uses (see [`draw_cell`]). Both planes are 12 rows × 36 cols,
//! so the shared dimension constants, render loops, cell resolution,
//! and glyph table apply to either. Result: a 6-row × 18-col rendered
//! banner.
//!
//! Terminal UI rendering lives in the binary crate. Core exposes only the
//! ANSI/data path used by startup welcome text.

/// A pixel-art plane plus its palette. Selected once per render
/// (P-51 vs rooster) so every render path draws from the same source.
struct Art {
    plane: &'static [&'static str; 12],
    palette: &'static [u8],
    color_discovery_order: ColorDiscoveryOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ColorDiscoveryOrder {
    Original,
    Mirrored,
}

/// Mirrored P-51 plane grid as 12 rows of 36 single-char cells, copied
/// verbatim from `p51-6-mirror.sh`'s `plane=(...)`. `.` = transparent;
/// `a`-`h` key into [`P51_PALETTE`].
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

/// ANSI 256-color palette, indexed by `'a'..='h'` − `'a'`. Mirrors the
/// `color_for` case statement shared by `p51-6.sh` and
/// `p51-6-mirror.sh`.
const P51_PALETTE: [u8; 8] = [0, 3, 6, 7, 8, 11, 14, 15];

/// Rooster plane grid as 12 rows of 36 single-char cells, copied
/// verbatim from `rooster-6.sh`'s `plane=(...)`. `.` = transparent;
/// `a`-`l` key into [`ROOSTER_PALETTE`].
const ROOSTER_PLANE: [&str; 12] = [
    ".........ii.........................",
    "........iiaii.......................",
    ".......jjiegb..........eeehhhha.....",
    ".........ebbddd......ce.eeeeeee.....",
    ".........ebdddd.....aeeeeeeee..e....",
    "........eebbdjjjh..llgheeeegeece....",
    "........eeeeaabbbibiighheeeeee.c....",
    "........eeeeeeiiibbejjdeeeeeke.e....",
    "..........eeeeeeeeedbb.eeec.k.......",
    ".............eeeeedddb.e....f.......",
    "..............eaeae.................",
    "...............d.d..................",
];

/// ANSI 256-color palette, indexed by `'a'..='l'` − `'a'`. Mirrors the
/// `color_for` case statement in `rooster-6.sh`. Wider than the P-51's.
const ROOSTER_PALETTE: [u8; 12] = [0, 1, 2, 3, 4, 6, 7, 8, 9, 11, 12, 15];

const PLANE_WIDTH: usize = 36;
const PLANE_HEIGHT: usize = 12;
/// Rendered banner width in terminal columns (one half-block glyph per
/// 2×2 cell group).
pub const RENDERED_WIDTH: usize = PLANE_WIDTH / 2;
/// Rendered banner height in terminal rows.
pub const RENDERED_HEIGHT: usize = PLANE_HEIGHT / 2;
/// Two-space left indent applied when rendering, matching the existing
/// `welcome.rs` chrome spacing.
const LEFT_INDENT: usize = 2;

const RESET: &str = "\x1b[0m";

/// Whether `COCKPIT_ROOSTER` is set to a truthy value — `true`, `1`,
/// or `yes`, case-insensitive. Any other value (`0`, `false`, empty,
/// unset, or unrecognized) is false. When true the rooster art renders
/// instead of the P-51; otherwise the P-51 shows as normal. The `cock`
/// shim sets `COCKPIT_ROOSTER=1`, which is truthy.
fn rooster_requested() -> bool {
    match std::env::var("COCKPIT_ROOSTER") {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"),
        Err(_) => false,
    }
}

/// Select the active art (plane + palette): the rooster when
/// [`rooster_requested`] is true, otherwise the P-51.
fn active_art() -> Art {
    if rooster_requested() {
        Art {
            plane: &ROOSTER_PLANE,
            palette: &ROOSTER_PALETTE,
            color_discovery_order: ColorDiscoveryOrder::Original,
        }
    } else {
        Art {
            plane: &P51_PLANE,
            palette: &P51_PALETTE,
            color_discovery_order: ColorDiscoveryOrder::Mirrored,
        }
    }
}

/// Render the active art (rooster when `COCKPIT_ROOSTER` is truthy,
/// else P-51) regardless of suppression rules. Useful for tests and for
/// callers (e.g. `/banner` debug commands later) that want the art
/// unconditionally.
pub fn render_unconditional() -> Vec<String> {
    let art = active_art();
    let indent = " ".repeat(LEFT_INDENT);
    let mut out = Vec::with_capacity(RENDERED_HEIGHT);
    for y in (0..PLANE_HEIGHT).step_by(2) {
        let top = art.plane[y].as_bytes();
        let bot = art.plane[y + 1].as_bytes();
        let mut line = indent.clone();
        for x in (0..PLANE_WIDTH).step_by(2) {
            line.push_str(&draw_cell(
                art.color_discovery_order,
                art.palette,
                top[x] as char,
                top[x + 1] as char,
                bot[x] as char,
                bot[x + 1] as char,
            ));
        }
        out.push(line);
    }
    out
}

/// Resolve one 2×2 cell group into `(glyph, fg, optional bg)`, or `None`
/// for an all-transparent group (rendered as a space). Mirrors
/// `draw_cell` in the source shell art:
///
/// 1. Find at most two distinct non-`.` colors in the four positions.
///    The mirrored P-51 uses `p51-6-mirror.sh`'s discovery order
///    (`ur`, `ul`, `lr`, `ll`); rooster keeps `rooster-6.sh`'s original
///    order (`ul`, `ur`, `ll`, `lr`).
/// 2. The first (call it A) becomes the foreground; the second (B,
///    if present) becomes the background.
/// 3. The four boolean "is this cell A?" bits index into a fixed
///    glyph table (16 entries, since the all-zero case is handled
///    separately as a single space).
fn cell_parts(
    color_discovery_order: ColorDiscoveryOrder,
    palette: &[u8],
    ul: char,
    ur: char,
    ll: char,
    lr: char,
) -> Option<(&'static str, u8, Option<u8>)> {
    let mut unique = [None; 4];
    let mut count = 0;
    let colors = match color_discovery_order {
        ColorDiscoveryOrder::Original => [ul, ur, ll, lr],
        ColorDiscoveryOrder::Mirrored => [ur, ul, lr, ll],
    };
    for &c in &colors {
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
    let bits = [(ul == a), (ur == a), (ll == a), (lr == a)];
    let glyph = glyph_for_pattern(bits);
    let fg = color_for(palette, a);
    let bg = unique[1].map(|c| color_for(palette, c));
    Some((glyph, fg, bg))
}

/// One 2×2 cell group as an ANSI-styled string (raw-stdout path).
fn draw_cell(
    color_discovery_order: ColorDiscoveryOrder,
    palette: &[u8],
    ul: char,
    ur: char,
    ll: char,
    lr: char,
) -> String {
    match cell_parts(color_discovery_order, palette, ul, ur, ll, lr) {
        None => " ".to_string(),
        Some((glyph, fg, Some(bg))) => format!("\x1b[38;5;{fg};48;5;{bg}m{glyph}{RESET}"),
        Some((glyph, fg, None)) => format!("\x1b[38;5;{fg}m{glyph}{RESET}"),
    }
}

fn color_for(palette: &[u8], c: char) -> u8 {
    let idx = (c as u8).wrapping_sub(b'a') as usize;
    *palette.get(idx).unwrap_or(&15)
}

/// Map the 4-bit "is this position A?" pattern to a Unicode block
/// glyph. The mapping comes from the source shell art; the all-zero
/// case is pre-filtered by [`draw_cell`] (returns a space).
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
        [false, false, false, false] => " ", // unreachable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_six_lines() {
        let lines = render_unconditional();
        assert_eq!(lines.len(), RENDERED_HEIGHT);
    }

    #[test]
    fn each_line_starts_with_two_space_indent() {
        for line in render_unconditional() {
            assert!(line.starts_with("  "), "missing indent in {line:?}");
        }
    }

    #[test]
    fn palette_size_matches_alphabet() {
        // P-51 a..h is 8 entries; rooster a..l is 12. Each palette
        // length must match its alphabet so color_for() never lands in
        // the fallback branch on valid inputs.
        assert_eq!(P51_PALETTE.len(), 8);
        assert_eq!(ROOSTER_PALETTE.len(), 12);
    }

    #[test]
    fn rooster_palette_matches_rooster_6_sh() {
        // The `color_for` case in rooster-6.sh: a→0 b→1 c→2 d→3 e→4
        // f→6 g→7 h→8 i→9 j→11 k→12 l→15.
        assert_eq!(ROOSTER_PALETTE, [0, 1, 2, 3, 4, 6, 7, 8, 9, 11, 12, 15]);
    }

    #[test]
    fn p51_palette_matches_mirrored_script() {
        assert_eq!(P51_PALETTE, [0, 3, 6, 7, 8, 11, 14, 15]);
    }

    #[test]
    fn plane_grid_is_uniform() {
        assert_eq!(P51_PLANE.len(), PLANE_HEIGHT);
        for (i, row) in P51_PLANE.iter().enumerate() {
            assert_eq!(row.chars().count(), PLANE_WIDTH, "row {i} width mismatch");
            for c in row.chars() {
                assert!(
                    c == '.' || matches!(c, 'a'..='h'),
                    "row {i} has unknown char `{c}`"
                );
            }
        }
    }

    #[test]
    fn p51_plane_matches_mirrored_script_shape_rows() {
        assert_eq!(P51_PLANE[0], "..........................hhhh......");
        assert_eq!(P51_PLANE[10], ".........hhhhh......................");
    }

    #[test]
    fn rooster_plane_grid_is_uniform() {
        assert_eq!(ROOSTER_PLANE.len(), PLANE_HEIGHT);
        for (i, row) in ROOSTER_PLANE.iter().enumerate() {
            assert_eq!(row.chars().count(), PLANE_WIDTH, "row {i} width mismatch");
            for c in row.chars() {
                assert!(
                    c == '.' || matches!(c, 'a'..='l'),
                    "row {i} has unknown char `{c}`"
                );
            }
        }
    }

    /// Serializes every test that mutates `COCKPIT_ROOSTER` so they
    /// don't race each other's set/restore (tests run in parallel by
    /// default). Each guarded test saves and restores the prior value.
    static ROOSTER_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Run `f` with `COCKPIT_ROOSTER` set to `value` (or removed when
    /// `None`), serialized against other rooster-env tests, restoring
    /// the prior value afterward — even on panic.
    fn with_rooster_env<R>(value: Option<&str>, f: impl FnOnce() -> R) -> R {
        let guard = ROOSTER_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var_os("COCKPIT_ROOSTER");
        match value {
            Some(v) => unsafe { std::env::set_var("COCKPIT_ROOSTER", v) },
            None => unsafe { std::env::remove_var("COCKPIT_ROOSTER") },
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        match prev {
            Some(v) => unsafe { std::env::set_var("COCKPIT_ROOSTER", v) },
            None => unsafe { std::env::remove_var("COCKPIT_ROOSTER") },
        }
        drop(guard);
        match result {
            Ok(r) => r,
            Err(e) => std::panic::resume_unwind(e),
        }
    }

    /// Set of distinct fg colors used across the active ANSI art.
    fn active_fg_colors() -> std::collections::BTreeSet<u8> {
        let mut seen = std::collections::BTreeSet::new();
        let art = active_art();
        for y in (0..PLANE_HEIGHT).step_by(2) {
            let top = art.plane[y].as_bytes();
            let bot = art.plane[y + 1].as_bytes();
            for x in (0..PLANE_WIDTH).step_by(2) {
                if let Some((_glyph, fg, _bg)) = cell_parts(
                    art.color_discovery_order,
                    art.palette,
                    top[x] as char,
                    top[x + 1] as char,
                    bot[x] as char,
                    bot[x + 1] as char,
                ) {
                    seen.insert(fg);
                }
            }
        }
        seen
    }

    #[test]
    fn default_p51_uses_mirrored_color_discovery_order() {
        with_rooster_env(None, || {
            let art = active_art();
            assert_eq!(art.plane, &P51_PLANE);
            assert_eq!(art.palette, &P51_PALETTE);
            assert_eq!(art.color_discovery_order, ColorDiscoveryOrder::Mirrored);

            let mirrored = cell_parts(
                ColorDiscoveryOrder::Mirrored,
                &P51_PALETTE,
                'a',
                'b',
                '.',
                '.',
            );
            let original = cell_parts(
                ColorDiscoveryOrder::Original,
                &P51_PALETTE,
                'a',
                'b',
                '.',
                '.',
            );
            assert_eq!(mirrored, Some(("▝", 3, Some(0))));
            assert_eq!(original, Some(("▘", 0, Some(3))));
        });
    }

    #[test]
    fn rooster_env_renders_rooster() {
        // A truthy COCKPIT_ROOSTER swaps the active art to the rooster:
        // correct row count, and colors drawn from the rooster palette.
        with_rooster_env(Some("1"), || {
            assert!(rooster_requested());
            let lines = render_unconditional();
            assert_eq!(lines.len(), RENDERED_HEIGHT);
            // The rooster uses palette entries the P-51 lacks (e.g. 1,
            // 2, 4, 9, 12), proving it draws from ROOSTER_PALETTE.
            let colors = active_fg_colors();
            assert!(
                colors.iter().any(|c| !P51_PALETTE.contains(c)),
                "rooster art should use colors outside the P-51 palette, got {colors:?}"
            );
        });
    }

    #[test]
    fn truthy_values_trigger_rooster() {
        for v in ["true", "TRUE", "True", "1", "yes", "YES", "Yes", " yes "] {
            with_rooster_env(Some(v), || {
                assert!(rooster_requested(), "value {v:?} should be truthy");
                assert_eq!(active_art().plane, &ROOSTER_PLANE);
            });
        }
    }

    #[test]
    fn non_truthy_values_fall_through_to_p51() {
        for v in [
            Some("0"),
            Some("false"),
            Some("FALSE"),
            Some(""),
            Some("on"),
            None,
        ] {
            with_rooster_env(v, || {
                assert!(!rooster_requested(), "value {v:?} should not be truthy");
                assert_eq!(active_art().plane, &P51_PLANE);
            });
        }
    }

    /// Visual smoke test. Run with `--nocapture` to see the banner.
    #[test]
    fn dump_for_visual_inspection() {
        eprintln!();
        for line in render_unconditional() {
            eprintln!("{line}");
        }
    }
}
