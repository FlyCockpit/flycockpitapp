use std::time::{Duration, Instant};

use crate::support::{
    COMPOSER_PLACEHOLDER, CellPos, HermeticCockpit, HermeticProfile, INITIAL_PTY_COLS,
    INITIAL_PTY_ROWS, ScreenSnapshot, SnapshotCell, sgr_left_click, sgr_left_down, sgr_left_up,
    sgr_motion,
};

const CLOSE_SETTINGS: &str = "[Close settings]";
const CHOOSE_DEFAULT: &str = "[Choose default model]";
const DEFAULT_MODEL_ROW: &str = "Default model for new sessions";
const MODEL_PICKER_MARKER: &str = "/model — pick the active model";
const HOVER_BG_RGB: (u8, u8, u8) = (0x2D, 0x5D, 0x8C);
const HOVER_BG_ANSI: u8 = 25;

fn launch_mouse_session(cols: u16, rows: u16) -> HermeticCockpit {
    let mut session = HermeticCockpit::prepare(HermeticProfile::Default);
    session.home().merge_tui_mouse_copy_config();
    session.start_trusted_daemon();
    session
        .spawn_pty(cols, rows)
        .expect("spawn hermetic PTY child");
    session
        .wait_until_ready(Duration::from_secs(30))
        .expect("ready TUI composer");
    assert!(
        session.snapshot().contains(COMPOSER_PLACEHOLDER),
        "ready composer required"
    );
    session
}

fn wait_for_text(session: &mut HermeticCockpit, marker: &str, timeout: Duration) {
    session
        .wait_until_screen(marker, timeout, |screen| screen.find_text(marker).is_some())
        .unwrap_or_else(|_| {
            panic!(
                "timed out waiting for marker; chat={:?}",
                session.snapshot().find_text(COMPOSER_PLACEHOLDER)
            )
        });
}

fn open_default_model_page(session: &mut HermeticCockpit) {
    session.open_settings();
    wait_for_text(session, CLOSE_SETTINGS, Duration::from_secs(5));
    let row = session
        .snapshot()
        .find_text(DEFAULT_MODEL_ROW)
        .expect("observed Default model row");
    specified_click(session, row, "open default-model page");
    wait_for_text(session, CHOOSE_DEFAULT, Duration::from_secs(5));
}

fn specified_click(session: &mut HermeticCockpit, pos: CellPos, label: &str) {
    let prev = session.output_bytes();
    session.write_bytes(&sgr_left_click(pos.sgr_x(), pos.sgr_y()));
    session.wait_for_output_progress(prev, label, Duration::from_secs(2));
}

fn specified_motion(session: &mut HermeticCockpit, pos: CellPos, label: &str) {
    let prev = session.output_bytes();
    session.write_bytes(&sgr_motion(pos.sgr_x(), pos.sgr_y()));
    session.wait_for_output_progress(prev, label, Duration::from_secs(2));
}

fn cell_hover(cell: &SnapshotCell) -> bool {
    cell.bg_rgb == Some(HOVER_BG_RGB) || cell.bg_index == Some(HOVER_BG_ANSI)
}

fn hover_cells(screen: &ScreenSnapshot) -> Vec<(u16, u16)> {
    screen
        .cells()
        .iter()
        .filter(|cell| cell_hover(cell))
        .map(|cell| (cell.row, cell.col))
        .collect()
}

fn wait_for_hover_on_span(
    session: &mut HermeticCockpit,
    start: CellPos,
    end: CellPos,
    label: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut delay = Duration::from_millis(2);
    loop {
        let snapshot = session.snapshot();
        let hovers = hover_cells(&snapshot);
        let covers = (start.col..=end.col)
            .all(|col| hovers.iter().any(|(row, c)| *row == start.row && *c == col));
        let only = hovers
            .iter()
            .all(|(row, col)| *row == start.row && *col >= start.col && *col <= end.col);
        if covers && only {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for exact hover ({label}); span=({},{}-{}) hover={:?}",
                start.row, start.col, end.col, hovers
            );
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

fn adjacent_cells(screen: &ScreenSnapshot, start: CellPos, end: CellPos) -> Vec<CellPos> {
    let mut out = Vec::new();
    if start.col > 0 {
        out.push(CellPos {
            row: start.row,
            col: start.col - 1,
        });
    }
    out.push(CellPos {
        row: start.row,
        col: end.col.saturating_add(1),
    });
    if start.row > 0 {
        out.push(CellPos {
            row: start.row - 1,
            col: start.col,
        });
    }
    out.retain(|pos| {
        screen
            .cells()
            .iter()
            .any(|cell| cell.row == pos.row && cell.col == pos.col)
    });
    out
}

#[test]
fn tui_pty_settings_button_hover_is_exact() {
    let mut session = launch_mouse_session(INITIAL_PTY_COLS, INITIAL_PTY_ROWS);
    session.open_settings();
    wait_for_text(&mut session, CLOSE_SETTINGS, Duration::from_secs(5));
    let (close_start, close_end) = session
        .snapshot()
        .find_text_span(CLOSE_SETTINGS)
        .expect("observed [Close settings]");
    specified_motion(&mut session, close_start, "hover close settings");
    wait_for_hover_on_span(&mut session, close_start, close_end, "close settings");
    let after_close = session.snapshot();
    for pos in adjacent_cells(&after_close, close_start, close_end) {
        let cell = after_close
            .cells()
            .iter()
            .find(|cell| cell.row == pos.row && cell.col == pos.col)
            .expect("adjacent cell");
        assert!(
            !cell_hover(cell),
            "adjacent cell hovered at ({},{})",
            pos.row,
            pos.col
        );
    }

    open_default_model_page(&mut session);
    let (choose_start, choose_end) = session
        .snapshot()
        .find_text_span(CHOOSE_DEFAULT)
        .expect("observed [Choose default model]");
    specified_motion(&mut session, choose_start, "hover choose default");
    wait_for_hover_on_span(
        &mut session,
        choose_start,
        choose_end,
        "choose default model",
    );
    let after_choose = session.snapshot();
    for pos in adjacent_cells(&after_choose, choose_start, choose_end) {
        let cell = after_choose
            .cells()
            .iter()
            .find(|cell| cell.row == pos.row && cell.col == pos.col)
            .expect("adjacent cell");
        assert!(
            !cell_hover(cell),
            "adjacent cell hovered at ({},{})",
            pos.row,
            pos.col
        );
    }
    session.reap();
    session.assert_reaped();
}

#[test]
fn tui_pty_settings_button_activation_is_exact() {
    let mut session = launch_mouse_session(INITIAL_PTY_COLS, INITIAL_PTY_ROWS);
    open_default_model_page(&mut session);
    let (choose_start, _) = session
        .snapshot()
        .find_text_span(CHOOSE_DEFAULT)
        .expect("observed [Choose default model]");
    let prev = session.output_bytes();
    session.write_bytes(&sgr_left_down(choose_start.sgr_x(), choose_start.sgr_y()));
    session.write_bytes(&sgr_left_up(choose_start.sgr_x(), choose_start.sgr_y()));
    session.wait_for_output_progress(prev, "activate choose default", Duration::from_secs(2));
    wait_for_text(&mut session, MODEL_PICKER_MARKER, Duration::from_secs(5));
    session.write_bytes(b"\x1b");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut delay = Duration::from_millis(2);
    while Instant::now() < deadline {
        if session.snapshot().find_text(CHOOSE_DEFAULT).is_some()
            || session.snapshot().contains("Choose default")
        {
            break;
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
    session.resize(23, 20);
    let prev = session.output_bytes();
    session.wait_for_output_progress(prev, "resize to 23x20", Duration::from_secs(2));
    let mut narrow = session;
    let snapshot = narrow.snapshot();
    let (partial_start, partial_end) = snapshot
        .find_text_span("[Choose default")
        .or_else(|| snapshot.find_text_span("Choose default"))
        .or_else(|| snapshot.find_text_span("[Choose"))
        .or_else(|| snapshot.find_text_span("Choose"))
        .unwrap_or((CellPos { row: 1, col: 1 }, CellPos { row: 1, col: 8 }));
    let absent_suffix = CellPos {
        row: partial_start.row,
        col: 22,
    };
    let before = narrow.snapshot();
    narrow.write_bytes(&sgr_left_down(absent_suffix.sgr_x(), absent_suffix.sgr_y()));
    narrow.write_bytes(&sgr_left_up(absent_suffix.sgr_x(), absent_suffix.sgr_y()));
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut delay = Duration::from_millis(2);
    while Instant::now() < deadline {
        assert!(
            !narrow.snapshot().contains("pick the active model"),
            "clipped suffix must not open the model picker; button={:?}-{:?}",
            partial_start,
            partial_end
        );
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
    let _ = before;
    narrow.reap();
    narrow.assert_reaped();
}
