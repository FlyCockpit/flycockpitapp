//! Golden screen-dump harness for `cockpit-tui`.
//!
//! Renders through [`ratatui::backend::TestBackend`] at the two review sizes
//! (80×24 and 120×40), writes plain-text dumps plus a `.style.txt` sidecar,
//! and compares both byte-for-byte. Set `COCKPIT_UPDATE_GOLDEN=1` to
//! regenerate only the dumps whose tests ran — the same convention as
//! `crates/cockpit-proto/tests/remote_transport_fixtures.rs`.
//!
//! Determinism pins (installed by [`GoldenPins`]):
//!
//! * clock — `HH:MM` stamps render as [`PINNED_HHMM`]
//! * frame — welcome fly-in uses [`PINNED_FRAME`]
//! * cloud seed — [`CLOUD_SEED`] for `clouds::seed_with(w, h, entropy)` (#428)
//! * hover — cleared unless the test calls [`GoldenPins::allow_hover`]
//! * colour — the palette resolves its truecolor RGB tokens regardless of
//!   the ambient `COLORTERM` (`theme::pin_truecolor(true)`), so dumps stay
//!   byte-identical on truecolor and 256-color terminals alike (#444)
//!
//! Visual reference for future UI work: `reference/example-tui/`.

use std::cell::{Cell, RefCell};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier};
use ratatui::widgets::Widget;

use crate::tui::onboarding::WELCOME_ANIMATION_FRAMES;

/// Review sizes every UI dump is captured at.
pub const SIZES: [(u16, u16); 2] = [(80, 24), (120, 40)];

/// Env var that rewrites the dumps whose tests ran.
pub const UPDATE_ENV: &str = "COCKPIT_UPDATE_GOLDEN";

/// Pinned `HH:MM` stamp used while [`GoldenPins`] is installed.
pub const PINNED_HHMM: &str = "12:00";

/// Pinned session-rail datetime used while [`GoldenPins`] is installed.
pub const PINNED_DATETIME: &str = "2020-01-15 12:00";

/// Cloud RNG entropy for `clouds::seed_with(w, h, entropy)` (#428).
pub const CLOUD_SEED: u64 = 1;

/// Settled welcome fly-in frame (`frame >= WELCOME_ANIMATION_FRAMES`).
pub const PINNED_FRAME: usize = WELCOME_ANIMATION_FRAMES;

const STYLE_HEADER: &str = "# style runs: count:fg/bg/mod  (mod is - or BOLD+DIM+…)\n";

thread_local! {
    static PINNED_CLOCK: Cell<bool> = const { Cell::new(false) };
    static HOVER_ALLOWED: Cell<bool> = const { Cell::new(false) };
    static CLOUD: Cell<Option<u64>> = const { Cell::new(None) };
    static FRAME: Cell<Option<usize>> = const { Cell::new(None) };
    static ROOT_OVERRIDE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
}

/// RAII install of the golden determinism pins.
pub struct GoldenPins {
    prev_clock: bool,
    prev_hover: bool,
    prev_cloud: Option<u64>,
    prev_frame: Option<usize>,
    /// Holds the truecolour pin for the guard's lifetime; its own Drop
    /// restores the previous capability when this guard drops.
    _truecolor: crate::tui::theme::TruecolorPin,
}

impl GoldenPins {
    /// Pin clock, frame, cloud seed, truecolour capability, and disable
    /// hover.
    pub fn install() -> Self {
        let prev_clock = PINNED_CLOCK.with(|cell| cell.replace(true));
        let prev_hover = HOVER_ALLOWED.with(|cell| cell.replace(false));
        let prev_cloud = CLOUD.with(|cell| cell.replace(Some(CLOUD_SEED)));
        let prev_frame = FRAME.with(|cell| cell.replace(Some(PINNED_FRAME)));
        let _truecolor = crate::tui::theme::pin_truecolor(true);
        Self {
            prev_clock,
            prev_hover,
            prev_cloud,
            prev_frame,
            _truecolor,
        }
    }

    /// Keep hover state the test set; otherwise [`crate::tui::app::golden::pin_app`]
    /// clears it.
    pub fn allow_hover(self) -> Self {
        HOVER_ALLOWED.with(|cell| cell.set(true));
        self
    }
}

impl Drop for GoldenPins {
    fn drop(&mut self) {
        PINNED_CLOCK.with(|cell| cell.set(self.prev_clock));
        HOVER_ALLOWED.with(|cell| cell.set(self.prev_hover));
        CLOUD.with(|cell| cell.set(self.prev_cloud));
        FRAME.with(|cell| cell.set(self.prev_frame));
    }
}

/// `Some(PINNED_HHMM)` while pins are installed.
pub fn pinned_hhmm() -> Option<&'static str> {
    PINNED_CLOCK.with(Cell::get).then_some(PINNED_HHMM)
}

/// `Some(PINNED_DATETIME)` while pins are installed.
pub fn pinned_datetime() -> Option<&'static str> {
    PINNED_CLOCK.with(Cell::get).then_some(PINNED_DATETIME)
}

/// Cloud entropy for `clouds::seed_with(w, h, entropy)` (#428).
///
/// While [`GoldenPins`] is installed this is [`CLOUD_SEED`]; otherwise it
/// still returns [`CLOUD_SEED`] so a missed `install()` cannot silently
/// pick wall-clock entropy. Live (non-golden) cloud rendering should
/// keep using its own realtime entropy and only pass this value from
/// tests.
pub fn cloud_seed() -> u64 {
    CLOUD.with(Cell::get).unwrap_or(CLOUD_SEED)
}

/// Frame counter pin for the welcome fly-in.
pub fn pinned_frame() -> usize {
    FRAME.with(Cell::get).unwrap_or(PINNED_FRAME)
}

/// Whether the test opted into hover.
pub fn hover_allowed() -> bool {
    HOVER_ALLOWED.with(Cell::get)
}

/// Directory holding `<area>/<screen>-<WxH>.txt` dumps.
pub fn golden_root() -> PathBuf {
    if let Some(override_root) = ROOT_OVERRIDE.with(|cell| cell.borrow().clone()) {
        return override_root;
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

/// Redirect dump I/O to `root` for harness unit tests.
pub struct GoldenRootGuard {
    prev: Option<PathBuf>,
}

impl GoldenRootGuard {
    pub fn override_root(root: PathBuf) -> Self {
        let prev = ROOT_OVERRIDE.with(|cell| cell.replace(Some(root)));
        Self { prev }
    }
}

impl Drop for GoldenRootGuard {
    fn drop(&mut self) {
        ROOT_OVERRIDE.with(|cell| cell.replace(self.prev.take()));
    }
}

fn update_golden() -> bool {
    std::env::var(UPDATE_ENV).is_ok()
}

/// Render any widget into a [`TestBackend`] buffer.
pub fn render_widget<W: Widget>(widget: W, width: u16, height: u16) -> Buffer {
    render_frame(width, height, |frame| {
        frame.render_widget(widget, frame.area());
    })
}

/// Render an arbitrary `Frame` callback through [`TestBackend`].
pub fn render_frame(width: u16, height: u16, draw: impl FnOnce(&mut ratatui::Frame<'_>)) -> Buffer {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("golden TestBackend");
    terminal.draw(draw).expect("golden draw");
    terminal.backend().buffer().clone()
}

/// Plain-text dump: one line per row, every cell `symbol()`, trailing newline.
pub fn buffer_text(buf: &Buffer) -> String {
    let area = *buf.area();
    let mut out = String::with_capacity(
        usize::from(area.width) * usize::from(area.height) + usize::from(area.height),
    );
    for y in 0..area.height {
        for x in 0..area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Style sidecar: header plus one line of `count:fg/bg/mod` runs per row.
pub fn buffer_style(buf: &Buffer) -> String {
    let area = *buf.area();
    let mut out = String::new();
    out.push_str(STYLE_HEADER);
    let _ = writeln!(out, "{}x{}", area.width, area.height);
    for y in 0..area.height {
        let mut line = String::new();
        let mut run_len: u16 = 0;
        let mut run_key: Option<(Color, Color, Modifier)> = None;
        for x in 0..area.width {
            let cell = &buf[(x, y)];
            let key = (cell.fg, cell.bg, cell.modifier);
            if run_key == Some(key) {
                run_len += 1;
                continue;
            }
            if let Some(prev) = run_key {
                push_style_run(&mut line, run_len, prev);
            }
            run_key = Some(key);
            run_len = 1;
        }
        if let Some(prev) = run_key {
            push_style_run(&mut line, run_len, prev);
        }
        let _ = writeln!(out, "{y}\t{line}");
    }
    out
}

fn push_style_run(line: &mut String, count: u16, (fg, bg, modifier): (Color, Color, Modifier)) {
    if !line.is_empty() {
        line.push(' ');
    }
    let _ = write!(
        line,
        "{count}:{}/{}/{}",
        format_color(fg),
        format_color(bg),
        format_modifier(modifier)
    );
}

fn format_color(color: Color) -> String {
    match color {
        Color::Reset => "Reset".into(),
        Color::Black => "Black".into(),
        Color::Red => "Red".into(),
        Color::Green => "Green".into(),
        Color::Yellow => "Yellow".into(),
        Color::Blue => "Blue".into(),
        Color::Magenta => "Magenta".into(),
        Color::Cyan => "Cyan".into(),
        Color::Gray => "Gray".into(),
        Color::DarkGray => "DarkGray".into(),
        Color::LightRed => "LightRed".into(),
        Color::LightGreen => "LightGreen".into(),
        Color::LightYellow => "LightYellow".into(),
        Color::LightBlue => "LightBlue".into(),
        Color::LightMagenta => "LightMagenta".into(),
        Color::LightCyan => "LightCyan".into(),
        Color::White => "White".into(),
        Color::Rgb(r, g, b) => format!("Rgb({r},{g},{b})"),
        Color::Indexed(index) => format!("Indexed({index})"),
    }
}

fn format_modifier(modifier: Modifier) -> String {
    const FLAGS: [(Modifier, &str); 9] = [
        (Modifier::BOLD, "BOLD"),
        (Modifier::DIM, "DIM"),
        (Modifier::ITALIC, "ITALIC"),
        (Modifier::UNDERLINED, "UNDERLINED"),
        (Modifier::SLOW_BLINK, "SLOW_BLINK"),
        (Modifier::RAPID_BLINK, "RAPID_BLINK"),
        (Modifier::REVERSED, "REVERSED"),
        (Modifier::HIDDEN, "HIDDEN"),
        (Modifier::CROSSED_OUT, "CROSSED_OUT"),
    ];
    let mut parts = Vec::new();
    for (flag, name) in FLAGS {
        if modifier.contains(flag) {
            parts.push(name);
        }
    }
    if parts.is_empty() {
        "-".into()
    } else {
        parts.join("+")
    }
}

fn dump_paths(area: &str, screen: &str, width: u16, height: u16) -> (PathBuf, PathBuf) {
    let stem = format!("{screen}-{width}x{height}");
    let dir = golden_root().join(area);
    (
        dir.join(format!("{stem}.txt")),
        dir.join(format!("{stem}.style.txt")),
    )
}

/// Compare `buf` to the checked-in dump, or rewrite it when `COCKPIT_UPDATE_GOLDEN` is set.
pub fn assert_golden(area: &str, screen: &str, width: u16, height: u16, buf: &Buffer) {
    assert_eq!(
        (buf.area().width, buf.area().height),
        (width, height),
        "buffer size must match the dump size {width}x{height}"
    );
    assert_files(
        area,
        screen,
        width,
        height,
        &buffer_text(buf),
        &buffer_style(buf),
    );
}

/// Render `render` at both review sizes and compare each dump.
pub fn assert_golden_sizes(area: &str, screen: &str, mut render: impl FnMut(u16, u16) -> Buffer) {
    for (width, height) in SIZES {
        let buf = render(width, height);
        assert_golden(area, screen, width, height, &buf);
    }
}

fn assert_files(area: &str, screen: &str, width: u16, height: u16, text: &str, style: &str) {
    let (text_path, style_path) = dump_paths(area, screen, width, height);
    assert_file(&text_path, text);
    assert_file(&style_path, style);
}

fn assert_file(path: &Path, actual: &str) {
    if update_golden() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap_or_else(|error| {
                panic!("create {}: {error}", parent.display());
            });
        }
        std::fs::write(path, actual).unwrap_or_else(|error| {
            panic!("write {}: {error}", path.display());
        });
        return;
    }

    let expected = std::fs::read_to_string(path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; regenerate with {UPDATE_ENV}=1 cargo test -p cockpit-tui golden",
            path.display()
        );
    });
    if expected != actual {
        panic!(
            "{} drifted; regenerate with {UPDATE_ENV}=1 cargo test -p cockpit-tui golden\n{}",
            path.display(),
            unified_diff(&expected, actual, &path.display().to_string())
        );
    }
}

fn unified_diff(expected: &str, actual: &str, expected_path: &str) -> String {
    similar::TextDiff::from_lines(expected, actual)
        .unified_diff()
        .context_radius(3)
        .header(expected_path, "rendered")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::widgets::Paragraph;

    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
            .unwrap_or_else(|| "non-string panic".into())
    }

    #[test]
    fn golden_pins_clock_frame_cloud_and_disables_hover() {
        assert!(pinned_hhmm().is_none());
        let pins = GoldenPins::install();
        assert_eq!(pinned_hhmm(), Some(PINNED_HHMM));
        assert_eq!(pinned_datetime(), Some(PINNED_DATETIME));
        assert_eq!(cloud_seed(), CLOUD_SEED);
        assert_eq!(pinned_frame(), PINNED_FRAME);
        assert!(!hover_allowed());
        // The colour pin makes every palette resolve deterministic: the
        // RGB tokens paint as themselves regardless of ambient COLORTERM.
        assert_eq!(
            crate::tui::theme::resolve_color(
                crate::tui::theme::BRASS,
                crate::tui::theme::BRASS_INDEX
            ),
            crate::tui::theme::BRASS
        );
        drop(pins.allow_hover());
        assert!(pinned_hhmm().is_none());
        assert!(!hover_allowed());
    }

    #[test]
    fn golden_render_widget_fills_the_backend() {
        let buf = render_widget(Paragraph::new("hello-golden"), 80, 24);
        let text = buffer_text(&buf);
        assert!(text.contains("hello-golden"));
        assert_eq!(text.lines().count(), 24);
        let style = buffer_style(&buf);
        assert!(style.starts_with(STYLE_HEADER));
        assert!(style.contains("80x24"));
    }

    #[test]
    fn golden_mismatch_prints_unified_diff() {
        let env = cockpit_test_support::TestEnvGuard::blocking_lock();
        env.remove_var(UPDATE_ENV);
        let tmp = tempfile::tempdir().expect("tmp");
        let _root = GoldenRootGuard::override_root(tmp.path().to_path_buf());
        let dir = tmp.path().join("probe");
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("screen-80x24.txt"), "hello\n").expect("text");
        std::fs::write(dir.join("screen-80x24.style.txt"), "ok\n").expect("style");

        let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_files("probe", "screen", 80, 24, "hallo\n", "ok\n");
        }))
        .expect_err("mismatch must panic");
        let message = panic_message(payload);
        assert!(
            message.contains("-hello") && message.contains("+hallo"),
            "readable unified diff, got:\n{message}"
        );
    }

    #[test]
    fn golden_assert_sizes_writes_both_review_dumps() {
        let tmp = tempfile::tempdir().expect("tmp");
        let _root = GoldenRootGuard::override_root(tmp.path().to_path_buf());
        let env = cockpit_test_support::TestEnvGuard::blocking_lock();
        env.set_var(UPDATE_ENV, "1");
        assert_golden_sizes("area", "screen", |width, height| {
            render_widget(Paragraph::new("x"), width, height)
        });
        for (width, height) in SIZES {
            let stem = format!("area/screen-{width}x{height}");
            assert!(
                tmp.path().join(format!("{stem}.txt")).is_file(),
                "{stem}.txt"
            );
            assert!(
                tmp.path().join(format!("{stem}.style.txt")).is_file(),
                "{stem}.style.txt"
            );
        }
    }

    #[test]
    fn golden_update_env_rewrites_only_ran_dumps() {
        let tmp = tempfile::tempdir().expect("tmp");
        let _root = GoldenRootGuard::override_root(tmp.path().to_path_buf());
        let env = cockpit_test_support::TestEnvGuard::blocking_lock();
        env.set_var(UPDATE_ENV, "1");

        let ran = tmp.path().join("ran/screen-80x24.txt");
        let skipped = tmp.path().join("skipped/other-80x24.txt");
        std::fs::create_dir_all(skipped.parent().expect("parent")).expect("dir");
        std::fs::write(&skipped, "untouched\n").expect("seed skipped");

        assert_files("ran", "screen", 80, 24, "fresh\n", "style\n");
        assert_eq!(std::fs::read_to_string(&ran).expect("ran"), "fresh\n");
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("ran/screen-80x24.style.txt")).expect("style"),
            "style\n"
        );
        assert_eq!(
            std::fs::read_to_string(&skipped).expect("skipped"),
            "untouched\n"
        );
    }
}
