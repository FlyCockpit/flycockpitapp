use super::{
    StartupFirstPaintTiming, reset_startup_first_paint_log_count, startup_first_paint_log_count,
    take_redraw_request,
};
use std::time::Instant;

#[test]
fn startup_timing_first_paint_logged_exactly_once() {
    let mut timing = StartupFirstPaintTiming::new(Some(Instant::now()));
    let mut needs_redraw = true;
    reset_startup_first_paint_log_count();

    if take_redraw_request(&mut needs_redraw) {
        timing.log_after_draw();
    }
    assert_eq!(startup_first_paint_log_count(), 1);

    needs_redraw = true;
    if take_redraw_request(&mut needs_redraw) {
        timing.log_after_draw();
    }
    assert_eq!(
        startup_first_paint_log_count(),
        1,
        "subsequent draws must not emit another startup first-paint event"
    );
}

#[test]
fn startup_timing_no_launch_instant_skips_first_paint_log() {
    let mut timing = StartupFirstPaintTiming::new(None);
    let mut needs_redraw = true;
    reset_startup_first_paint_log_count();

    if take_redraw_request(&mut needs_redraw) {
        timing.log_after_draw();
    }
    assert_eq!(startup_first_paint_log_count(), 0);

    needs_redraw = true;
    if take_redraw_request(&mut needs_redraw) {
        timing.log_after_draw();
    }
    assert_eq!(startup_first_paint_log_count(), 0);
}
