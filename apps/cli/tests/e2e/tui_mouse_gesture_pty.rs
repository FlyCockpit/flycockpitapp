use std::time::{Duration, Instant};

use cockpit_test_support::provider::{ScriptedProvider, Turn};

use crate::support::{
    COMPOSER_PLACEHOLDER, CellPos, HermeticCockpit, HermeticProfile, INITIAL_PTY_COLS,
    INITIAL_PTY_ROWS, Osc52Observer, ScreenSnapshot, sgr_left_click, sgr_left_down, sgr_left_drag,
    sgr_left_up, sgr_motion, sgr_wheel_up, sha256_hex,
};

const USER_INPUT: &str = "PTY gesture input";
const HEAD_MARKER: &str = "PTY GESTURE RESPONSE alpha beta";
const HEAD_PREFIX: &str = "PTY GESTURE RESPONSE";
const TAIL_MARKER: &str = "PTY GESTURE RESPONSE omega";
const WORD_MARKER: &str = "alpha";
const MAX_WHEEL_EVENTS: usize = 80;
const MUTED_COLOR_INDEX: u8 = 250;

fn gesture_completion() -> String {
    let mut lines = Vec::with_capacity(80);
    lines.push(HEAD_MARKER.to_string());
    for idx in 2..80 {
        lines.push(format!("PTY GESTURE FILL {idx:03}"));
    }
    lines.push(TAIL_MARKER.to_string());
    // Paragraph breaks (`\n\n`) are required: a single `\n` is a Markdown
    // soft break and collapses the 80 records so the tail marker is not
    // an observed unwrapped line.
    lines.join("\n\n")
}

fn expected_head_copy_meta() -> (usize, String) {
    (HEAD_MARKER.len(), sha256_hex(HEAD_MARKER.as_bytes()))
}

fn launch_scrolled_gesture_session() -> (ScriptedProvider, HermeticCockpit) {
    let provider = ScriptedProvider::builder()
        .turn(Turn::Text(gesture_completion()))
        .repeat_last()
        .start_blocking();
    let mut session = HermeticCockpit::prepare(HermeticProfile::RemoteOsc52);
    session
        .home()
        .write_scripted_provider_with_tui_mouse(&provider.base_url());
    session.enable_isolated_secret_service();
    session.start_trusted_daemon();
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn hermetic PTY child");
    session
        .wait_until_ready(Duration::from_secs(30))
        .expect("ready TUI composer");
    assert!(
        session.snapshot().contains(COMPOSER_PLACEHOLDER),
        "ready composer required before PTY gesture input"
    );
    submit_gesture_input(&mut session, &provider);
    wait_for_marker(
        &mut session,
        &provider,
        TAIL_MARKER,
        Duration::from_secs(30),
    );
    scroll_until_head(&mut session);
    (provider, session)
}

fn submit_gesture_input(session: &mut HermeticCockpit, provider: &ScriptedProvider) {
    session.write_str(USER_INPUT);
    wait_for_marker(session, provider, USER_INPUT, Duration::from_secs(5));
    session.send_enter();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut delay = Duration::from_millis(2);
    loop {
        let snapshot = session.snapshot();
        let submitted = snapshot.contains(COMPOSER_PLACEHOLDER)
            || snapshot.contains(TAIL_MARKER)
            || provider.request_count() > 0;
        if submitted && snapshot.contains(COMPOSER_PLACEHOLDER) {
            return;
        }
        if snapshot.contains(TAIL_MARKER) {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "composer did not submit; requests={} chat={:?}",
                provider.request_count(),
                observed_chat_coord(&snapshot)
            );
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

fn wait_for_marker(
    session: &mut HermeticCockpit,
    provider: &ScriptedProvider,
    marker: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(2);
    loop {
        if session.snapshot().find_text(marker).is_some() {
            return;
        }
        if Instant::now() >= deadline {
            let snapshot = session.snapshot();
            panic!(
                "timed out waiting for marker; last chat coord={:?} requests={}",
                observed_chat_coord(&snapshot),
                provider.request_count()
            );
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

fn scroll_until_head(session: &mut HermeticCockpit) {
    for event_n in 0..MAX_WHEEL_EVENTS {
        let snapshot = session.snapshot();
        if head_visible(&snapshot) {
            return;
        }
        let Some(pos) = observed_chat_coord(&snapshot) else {
            panic!("wheel {event_n}: no observed chat-area coordinate for marker");
        };
        let before = snapshot.visible_state();
        session.write_bytes(&sgr_wheel_up(pos.sgr_x(), pos.sgr_y()));
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut delay = Duration::from_millis(2);
        loop {
            let now = session.snapshot();
            if head_visible(&now) || now.visible_state() != before {
                break;
            }
            if Instant::now() >= deadline {
                panic!(
                    "wheel {event_n} did not change the current screen; coord={:?} rows={:?}",
                    pos,
                    visible_row_markers(&now)
                );
            }
            std::thread::sleep(delay);
            delay = (delay * 2).min(Duration::from_millis(50));
        }
    }
    panic!(
        "head marker still hidden after {MAX_WHEEL_EVENTS} wheels; last chat coord={:?} rows={:?}",
        observed_chat_coord(&session.snapshot()),
        visible_row_markers(&session.snapshot())
    );
}

fn head_visible(screen: &ScreenSnapshot) -> bool {
    observed_head_span(screen).is_some()
}

fn observed_head_span(screen: &ScreenSnapshot) -> Option<(CellPos, CellPos)> {
    screen.find_text_span(HEAD_MARKER).or_else(|| {
        let (start, _) = screen.find_text_span(HEAD_PREFIX)?;
        let row = screen.row_text(start.row);
        if !row.contains(WORD_MARKER) {
            return None;
        }
        screen
            .find_text_span("beta")
            .filter(|(beta, _)| beta.row == start.row)
            .map(|(_, beta_end)| (start, beta_end))
            .or_else(|| {
                screen
                    .find_text_span(WORD_MARKER)
                    .filter(|(word, _)| word.row == start.row)
                    .map(|(_, word_end)| (start, word_end))
            })
    })
}

fn observed_chat_coord(screen: &ScreenSnapshot) -> Option<CellPos> {
    observed_head_span(screen)
        .map(|(start, _)| start)
        .or_else(|| screen.find_text(TAIL_MARKER))
        .or_else(|| screen.find_text("PTY GESTURE FILL"))
        .or_else(|| screen.find_text(HEAD_PREFIX))
        .or_else(|| screen.find_text(USER_INPUT))
}

fn visible_row_markers(screen: &ScreenSnapshot) -> Vec<(u16, &'static str)> {
    let (rows, _) = screen.size();
    (0..rows.min(8))
        .map(|row| {
            let text = screen.row_text(row);
            let marker = if text.contains(HEAD_MARKER) {
                "head"
            } else if text.contains(TAIL_MARKER) {
                "tail"
            } else if text.contains(HEAD_PREFIX) {
                "head-prefix"
            } else if text.contains("PTY GESTURE FILL") {
                "fill"
            } else if text.contains(USER_INPUT) {
                "user"
            } else if text.contains(COMPOSER_PLACEHOLDER) {
                "composer"
            } else if text.trim().is_empty() {
                "blank"
            } else {
                "other"
            };
            (row, marker)
        })
        .collect()
}

fn inverse_coords(screen: &ScreenSnapshot) -> Vec<(u16, u16)> {
    screen
        .cells()
        .iter()
        .filter(|cell| cell.inverse)
        .map(|cell| (cell.row, cell.col))
        .collect()
}

fn osc_generation(observer: &Osc52Observer) -> (usize, usize) {
    let copies = observer
        .frames()
        .iter()
        .filter(|frame| frame.selector == 'c')
        .count();
    (observer.frame_count(), copies)
}

fn last_copy_meta(observer: &Osc52Observer) -> Option<(usize, String)> {
    observer
        .frames()
        .iter()
        .rev()
        .find(|frame| frame.selector == 'c')
        .map(|frame| (frame.decoded_len, frame.sha256.clone()))
}

fn toast_kind(screen: &ScreenSnapshot) -> &'static str {
    if screen.contains("Copied") {
        "copied"
    } else if screen.contains("Copy failed") {
        "failed"
    } else if screen.contains("too large") {
        "too_large"
    } else if screen.contains("unverified") {
        "unverified"
    } else {
        "none"
    }
}

fn wait_for_one_copy_frame(
    session: &mut HermeticCockpit,
    before: (usize, usize),
) -> (usize, String) {
    let (expected_len, expected_sha) = expected_head_copy_meta();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut delay = Duration::from_millis(2);
    loop {
        let observer = session.osc52();
        let (frames, count) = osc_generation(&observer);
        if frames == before.0 + 1
            && count == before.1 + 1
            && let Some((len, sha)) = last_copy_meta(&observer)
        {
            assert_eq!(
                (len, sha.as_str()),
                (expected_len, expected_sha.as_str()),
                "copy metadata mismatch (selector=c len={len})"
            );
            return (len, sha);
        }
        let snapshot = session.snapshot();
        assert!(
            Instant::now() < deadline,
            "timed out waiting for one selector-c frame (before={before:?} now=({frames},{count}) rejected_inc={} rejected_over={} frames={}) inverse={:?} head={:?} toast={}",
            observer.rejected_incomplete(),
            observer.rejected_over_limit(),
            observer.frame_count(),
            inverse_coords(&snapshot),
            observed_head_span(&snapshot),
            toast_kind(&snapshot)
        );
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

fn wait_for_inverse(session: &mut HermeticCockpit, label: &str) {
    if wait_for_inverse_until(session, Duration::from_secs(2)) {
        return;
    }
    panic!(
        "timed out waiting for inverse ({label}); chat={:?} inverse={:?}",
        observed_chat_coord(&session.snapshot()),
        inverse_coords(&session.snapshot())
    );
}

fn wait_for_inverse_span(session: &mut HermeticCockpit, start: CellPos, end: CellPos, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut delay = Duration::from_millis(2);
    loop {
        let snapshot = session.snapshot();
        if inverse_matches_span(&snapshot, start, end) {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for inverse span ({label}); chat={:?} inverse={:?}",
                observed_chat_coord(&snapshot),
                inverse_coords(&snapshot)
            );
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

fn wait_for_observed_line_inverse(session: &mut HermeticCockpit, row: u16, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut delay = Duration::from_millis(2);
    loop {
        let snapshot = session.snapshot();
        if let Some((start, end)) = snapshot.row_content_span(row)
            && inverse_matches_span(&snapshot, start, end)
        {
            return;
        }
        if Instant::now() >= deadline {
            panic!(
                "timed out waiting for observed line inverse ({label}); chat={:?} inverse={:?}",
                observed_chat_coord(&snapshot),
                inverse_coords(&snapshot)
            );
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

fn inverse_matches_span(screen: &ScreenSnapshot, start: CellPos, end: CellPos) -> bool {
    if start.row != end.row {
        return false;
    }
    let inverses = inverse_coords(screen);
    if inverses.is_empty() {
        return false;
    }
    for col in start.col..=end.col {
        if !inverses
            .iter()
            .any(|(row, c)| *row == start.row && *c == col)
        {
            return false;
        }
    }
    inverses
        .iter()
        .all(|(row, col)| *row == start.row && *col >= start.col && *col <= end.col)
}

fn wait_for_inverse_until(session: &mut HermeticCockpit, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(2);
    loop {
        if session.snapshot().has_inverse() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

fn retry_until_inverse(
    session: &mut HermeticCockpit,
    label: &str,
    mut act: impl FnMut(&mut HermeticCockpit),
) {
    for _ in 0..4 {
        act(session);
        if wait_for_inverse_until(session, Duration::from_secs(1)) {
            return;
        }
        if let Some(pos) = observed_chat_coord(&session.snapshot()) {
            session.write_bytes(&sgr_left_up(pos.sgr_x(), pos.sgr_y()));
        }
        session.write_bytes(b"\x1b");
        let _ = wait_for_inverse_until(session, Duration::from_millis(200));
    }
    wait_for_inverse(session, label);
}

/// Hold a drag until the current-screen observer paints inverse, then release.
///
/// Production captures `chat_text_grid` only on a render that already has a
/// selection. A same-drain Down+Drag+Up therefore extracts empty text and
/// never emits OSC52. The painted inverse is the render boundary that arms
/// copy-on-release.
fn drag_head_until_painted(session: &mut HermeticCockpit) -> CellPos {
    retry_until_inverse(session, "drag selection", |session| {
        let (start, end) = observed_head_span(&session.snapshot()).expect("observed head marker");
        drag_between(session, start, end, false);
    });
    let snapshot = session.snapshot();
    let (start, end) = observed_head_span(&snapshot).expect("observed head marker");
    assert_inverse_only_span(&snapshot, start, end);
    end
}

fn wait_for_no_inverse(session: &mut HermeticCockpit, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut delay = Duration::from_millis(2);
    loop {
        if !session.snapshot().has_inverse() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for inverse clear ({label}); coords={:?}",
            inverse_coords(&session.snapshot())
        );
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(50));
    }
}

fn assert_no_selection(screen: &ScreenSnapshot) {
    assert!(
        !screen.has_inverse(),
        "unexpected selection inverse at {:?}",
        inverse_coords(screen)
    );
}

fn assert_inverse_only_span(screen: &ScreenSnapshot, start: CellPos, end: CellPos) {
    assert_eq!(start.row, end.row, "span must be a single observed row");
    let inverses = inverse_coords(screen);
    for col in start.col..=end.col {
        assert!(
            inverses
                .iter()
                .any(|(row, c)| *row == start.row && *c == col),
            "expected inverse on observed cell ({},{})",
            start.row,
            col
        );
    }
    for (row, col) in &inverses {
        assert_eq!(
            *row, start.row,
            "inverse outside observed row at ({row},{col})"
        );
        assert!(
            *col >= start.col && *col <= end.col,
            "inverse outside observed span at ({row},{col})"
        );
    }
}

fn find_muted_footer_separator(screen: &ScreenSnapshot) -> CellPos {
    let (rows, _) = screen.size();
    let status_row = rows.saturating_sub(1);
    if let Some(cell) = screen.cells().iter().find(|cell| {
        cell.row == status_row
            && cell.fg_index == Some(MUTED_COLOR_INDEX)
            && (cell.text == "·" || cell.text == "─")
    }) {
        return CellPos {
            row: cell.row,
            col: cell.col,
        };
    }
    panic!(
        "muted footer separator not observed; status_row={status_row} chat={:?}",
        observed_chat_coord(screen)
    );
}

fn find_blank_gap(screen: &ScreenSnapshot) -> CellPos {
    let (rows, _) = screen.size();
    let composer_row = screen
        .find_text(COMPOSER_PLACEHOLDER)
        .map(|pos| pos.row)
        .or_else(|| {
            (0..rows)
                .rev()
                .find(|&row| screen.row_text(row).contains('╭'))
        })
        .unwrap_or(rows);
    let (rows, _) = screen.size();
    let limit = composer_row.min(rows);
    for row in 0..limit {
        if !row_is_blank(screen, row) {
            continue;
        }
        let above = row > 0 && !row_is_blank(screen, row.saturating_sub(1));
        let below = row + 1 < limit && !row_is_blank(screen, row + 1);
        if above && below {
            let cell = screen
                .cells()
                .iter()
                .find(|cell| cell.row == row && cell.text.chars().all(char::is_whitespace))
                .expect("blank gap row has an observed empty cell");
            return CellPos {
                row: cell.row,
                col: cell.col,
            };
        }
    }
    panic!(
        "blank gap not observed; composer_row={composer_row} chat={:?}",
        observed_chat_coord(screen)
    );
}

fn observed_same_row_neighbor(screen: &ScreenSnapshot, origin: CellPos) -> CellPos {
    screen
        .cells()
        .iter()
        .find(|cell| cell.row == origin.row && cell.col > origin.col)
        .map(|cell| CellPos {
            row: cell.row,
            col: cell.col,
        })
        .expect("observed neighbor on the same row")
}

fn row_is_blank(screen: &ScreenSnapshot, row: u16) -> bool {
    screen
        .row_text(row)
        .chars()
        .all(|ch| ch.is_whitespace() || ch == '\0')
}

fn click_and_checkpoint(session: &mut HermeticCockpit, pos: CellPos) {
    specified_input_checkpoint(
        session,
        &sgr_left_click(pos.sgr_x(), pos.sgr_y()),
        "click render checkpoint",
    );
}

/// Write one specified input and wait for the child to emit the next render.
fn specified_input_checkpoint(session: &mut HermeticCockpit, bytes: &[u8], label: &str) {
    let prev = session.output_bytes();
    session.write_bytes(bytes);
    session.wait_for_output_progress(prev, label, Duration::from_secs(2));
}

fn drag_bytes(start: CellPos, end: CellPos, release: bool) -> Vec<u8> {
    let mid = CellPos {
        row: start.row,
        col: start
            .col
            .saturating_add(end.col.saturating_sub(start.col) / 2),
    };
    let mut bytes = sgr_left_down(start.sgr_x(), start.sgr_y());
    bytes.extend_from_slice(&sgr_left_drag(mid.sgr_x(), mid.sgr_y()));
    bytes.extend_from_slice(&sgr_left_drag(end.sgr_x(), end.sgr_y()));
    if release {
        bytes.extend_from_slice(&sgr_left_up(end.sgr_x(), end.sgr_y()));
    }
    bytes
}

fn drag_between(session: &mut HermeticCockpit, start: CellPos, end: CellPos, release: bool) {
    session.write_bytes(&drag_bytes(start, end, release));
}

#[test]
fn tui_mouse_bare_click_pty() {
    let (_provider, mut session) = launch_scrolled_gesture_session();
    let osc_before = osc_generation(&session.osc52());
    let alpha = session
        .snapshot()
        .find_text(WORD_MARKER)
        .expect("observed alpha");
    specified_input_checkpoint(
        &mut session,
        &sgr_left_click(alpha.sgr_x(), alpha.sgr_y()),
        "bare-click render checkpoint",
    );
    assert_no_selection(&session.snapshot());
    assert_eq!(osc_generation(&session.osc52()), osc_before);
    specified_input_checkpoint(
        &mut session,
        &sgr_motion(alpha.sgr_x(), alpha.sgr_y()),
        "bare-click motion checkpoint",
    );
    assert_no_selection(&session.snapshot());
    assert_eq!(osc_generation(&session.osc52()), osc_before);
    session.reap();
    session.assert_reaped();
}

#[test]
fn tui_mouse_drag_auto_copy_pty() {
    let (_provider, mut session) = launch_scrolled_gesture_session();
    let osc_before = osc_generation(&session.osc52());
    let end = drag_head_until_painted(&mut session);
    session.write_bytes(&sgr_left_up(end.sgr_x(), end.sgr_y()));
    let _meta = wait_for_one_copy_frame(&mut session, osc_before);
    specified_input_checkpoint(
        &mut session,
        &sgr_motion(end.sgr_x(), end.sgr_y()),
        "post-copy motion checkpoint",
    );
    let after = session.osc52();
    assert_eq!(
        osc_generation(&after),
        (osc_before.0 + 1, osc_before.1 + 1)
    );
    let (len, sha) = last_copy_meta(&after).expect("retained selector-c frame");
    let (expected_len, expected_sha) = expected_head_copy_meta();
    assert_eq!(len, expected_len, "copy length changed after checkpoint");
    assert_eq!(sha, expected_sha, "copy digest changed after checkpoint");
    session.reap();
    session.assert_reaped();
}

#[test]
fn tui_mouse_multiclick_pty() {
    let (_provider, mut session) = launch_scrolled_gesture_session();
    let head_row = observed_head_span(&session.snapshot())
        .map(|(start, _)| start.row)
        .expect("observed head row");
    let alpha = session
        .snapshot()
        .find_text_span(WORD_MARKER)
        .and_then(|(start, _)| (start.row == head_row).then_some(start))
        .expect("observed alpha");
    // Word/line spans read `chat_text_grid`, which production captures
    // only while a selection already exists. Prime that cache with a
    // painted drag, then send the required multi-click sequence.
    let primed = drag_head_until_painted(&mut session);
    session.write_bytes(&sgr_left_up(primed.sgr_x(), primed.sgr_y()));
    let mut double_click = sgr_left_click(alpha.sgr_x(), alpha.sgr_y());
    double_click.extend_from_slice(&sgr_left_click(alpha.sgr_x(), alpha.sgr_y()));
    session.write_bytes(&double_click);
    let (word_start, word_end) = session
        .snapshot()
        .find_text_span(WORD_MARKER)
        .filter(|(start, _)| start.row == head_row)
        .expect("observed alpha span");
    wait_for_inverse_span(&mut session, word_start, word_end, "double-click word");
    assert_inverse_only_span(&session.snapshot(), word_start, word_end);

    // Esc must not be concatenated with SGR: `\x1b` + `\x1b[<...` is one
    // ambiguous CSI. Reset first, then re-prime the grid and send a
    // fresh three-click sequence.
    session.write_bytes(b"\x1b");
    wait_for_no_inverse(&mut session, "esc reset");
    assert_no_selection(&session.snapshot());
    let primed = drag_head_until_painted(&mut session);
    session.write_bytes(&sgr_left_up(primed.sgr_x(), primed.sgr_y()));
    let (line_start, _) = observed_head_span(&session.snapshot()).expect("observed head line");
    let mut triple_click = Vec::new();
    for _ in 0..3 {
        triple_click.extend_from_slice(&sgr_left_click(line_start.sgr_x(), line_start.sgr_y()));
    }
    session.write_bytes(&triple_click);
    wait_for_observed_line_inverse(&mut session, line_start.row, "triple-click line");
    let snapshot = session.snapshot();
    let (line_start, line_end) = snapshot
        .row_content_span(line_start.row)
        .expect("observed line content");
    assert_inverse_only_span(&snapshot, line_start, line_end);
    session.reap();
    session.assert_reaped();
}

#[test]
fn tui_mouse_chrome_gap_scroll_pty() {
    let (_provider, mut session) = launch_scrolled_gesture_session();
    let osc_before = osc_generation(&session.osc52());
    let footer = find_muted_footer_separator(&session.snapshot());
    let gap = find_blank_gap(&session.snapshot());

    click_and_checkpoint(&mut session, footer);
    assert_no_selection(&session.snapshot());
    assert_eq!(osc_generation(&session.osc52()), osc_before);

    let gap = session
        .snapshot()
        .cells()
        .iter()
        .find(|cell| cell.row == gap.row && cell.col == gap.col)
        .map(|cell| CellPos {
            row: cell.row,
            col: cell.col,
        })
        .unwrap_or(gap);
    click_and_checkpoint(&mut session, gap);
    assert_no_selection(&session.snapshot());
    assert_eq!(osc_generation(&session.osc52()), osc_before);

    retry_until_inverse(
        &mut session,
        "content drag before wheel cancel",
        |session| {
            let (start, end) =
                observed_head_span(&session.snapshot()).expect("observed head marker");
            drag_between(session, start, end, false);
        },
    );
    let chat = observed_chat_coord(&session.snapshot()).expect("chat-area coordinate for wheel");
    session.write_bytes(&sgr_wheel_up(chat.sgr_x(), chat.sgr_y()));
    wait_for_no_inverse(&mut session, "wheel cancelled drag");
    let mut release_and_motion = Vec::new();
    if let Some((_, end)) = observed_head_span(&session.snapshot()) {
        release_and_motion.extend_from_slice(&sgr_left_up(end.sgr_x(), end.sgr_y()));
    }
    release_and_motion.extend_from_slice(&sgr_motion(chat.sgr_x(), chat.sgr_y()));
    specified_input_checkpoint(
        &mut session,
        &release_and_motion,
        "cancelled-drag release checkpoint",
    );
    assert_no_selection(&session.snapshot());
    assert_eq!(osc_generation(&session.osc52()), osc_before);

    let footer = find_muted_footer_separator(&session.snapshot());
    let footer_end = observed_same_row_neighbor(&session.snapshot(), footer);
    specified_input_checkpoint(
        &mut session,
        &drag_bytes(footer, footer_end, true),
        "chrome drag checkpoint",
    );
    assert_no_selection(&session.snapshot());
    assert_eq!(osc_generation(&session.osc52()), osc_before);

    let gap = find_blank_gap(&session.snapshot());
    let gap_end = observed_same_row_neighbor(&session.snapshot(), gap);
    specified_input_checkpoint(
        &mut session,
        &drag_bytes(gap, gap_end, true),
        "gap drag checkpoint",
    );
    assert_no_selection(&session.snapshot());
    assert_eq!(osc_generation(&session.osc52()), osc_before);

    session.reap();
    session.assert_reaped();
}
