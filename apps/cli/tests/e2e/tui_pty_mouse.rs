use std::time::Duration;

use crate::support::{
    COMPOSER_PLACEHOLDER, CellPos, HermeticCockpit, HermeticProfile, INITIAL_PTY_COLS,
    INITIAL_PTY_ROWS, sgr_left_click, sgr_left_drag, sgr_malformed_complete, sgr_middle_click,
    sgr_motion, sgr_right_click, sgr_wheel_down, sgr_wheel_up, x10_mouse,
};

#[test]
fn tui_pty_mouse_protocol_coordinates() {
    let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
    let composer_before = session.snapshot().contains(COMPOSER_PLACEHOLDER);
    assert!(composer_before, "ready composer required before /settings");

    session.open_settings();
    let close = session
        .snapshot()
        .find_text("[Close settings]")
        .expect("locate [Close settings]");
    session.write_bytes(&sgr_left_click(close.sgr_x(), close.sgr_y()));
    session
        .wait_until_screen(
            "settings closed by SGR left click",
            Duration::from_secs(5),
            |screen| !screen.contains("[Close settings]") && screen.contains(COMPOSER_PLACEHOLDER),
        )
        .expect("click [Close settings]");
    assert!(
        session.snapshot().contains(COMPOSER_PLACEHOLDER),
        "composer marker must remain after closing settings"
    );

    let complete_cases = complete_noop_sequences(close);
    for (label, bytes) in complete_cases {
        session.open_settings();
        let before = session.snapshot();
        session.write_bytes(&bytes);
        session.checkpoint_input_with_redraw();
        assert_eq!(
            session.snapshot().visible_state(),
            before.visible_state(),
            "{label} changed the current visible cell grid or composer marker"
        );
    }

    let incomplete = [
        ("csi-open", b"\x1b[<".as_slice()),
        ("partial-button", b"\x1b[<0;".as_slice()),
        ("partial-sgr", b"\x1b[<0;4;3".as_slice()),
    ];
    for (label, bytes) in incomplete {
        let mut isolated = HermeticCockpit::launch_ready(HermeticProfile::Default);
        isolated.open_settings();
        let before = isolated.snapshot();
        isolated.write_bytes(bytes);
        isolated.checkpoint_input_with_redraw();
        assert_eq!(
            isolated.snapshot().visible_state(),
            before.visible_state(),
            "{label} changed the current visible cell grid or composer marker"
        );
        isolated.reap();
        isolated.assert_reaped();
    }
}

fn complete_noop_sequences(close: CellPos) -> Vec<(&'static str, Vec<u8>)> {
    let top_left = CellPos { row: 0, col: 0 };
    let final_cell = CellPos {
        row: INITIAL_PTY_ROWS - 1,
        col: INITIAL_PTY_COLS - 1,
    };
    let adjacent = CellPos {
        row: close.row,
        col: close.col.saturating_add(16),
    };
    let outside_x = INITIAL_PTY_COLS.saturating_add(2);
    let outside_y = INITIAL_PTY_ROWS.saturating_add(2);
    let mut wheel = sgr_wheel_up(close.sgr_x(), close.sgr_y());
    wheel.extend_from_slice(&sgr_wheel_down(close.sgr_x(), close.sgr_y()));
    vec![
        (
            "top-left",
            sgr_left_click(top_left.sgr_x(), top_left.sgr_y()),
        ),
        (
            "final-cell",
            sgr_left_click(final_cell.sgr_x(), final_cell.sgr_y()),
        ),
        (
            "adjacent/outside-adjacent",
            sgr_left_click(adjacent.sgr_x(), adjacent.sgr_y()),
        ),
        (
            "adjacent/outside-outside",
            sgr_left_click(outside_x, outside_y),
        ),
        (
            "completed-malformed",
            sgr_malformed_complete(0, close.sgr_x(), close.sgr_y()),
        ),
        ("drag", sgr_left_drag(close.sgr_x(), close.sgr_y())),
        ("motion", sgr_motion(close.sgr_x(), close.sgr_y())),
        ("wheel", wheel),
        ("non-primary", {
            let mut bytes = sgr_middle_click(close.sgr_x(), close.sgr_y());
            bytes.extend_from_slice(&sgr_right_click(close.sgr_x(), close.sgr_y()));
            // X10 is a non-SGR encoding; use the middle button so this is
            // not a primary left-click at the close target.
            bytes.extend_from_slice(&x10_mouse(1, close.sgr_x(), close.sgr_y()));
            bytes
        }),
    ]
}
