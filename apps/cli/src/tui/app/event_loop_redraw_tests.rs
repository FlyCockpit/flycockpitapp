use super::{
    EVENT_LOOP_DRAW_CALL_COUNT, event_loop_draw_call_count, reset_event_loop_draw_call_count,
    take_redraw_request,
};
use std::sync::atomic::Ordering;

#[test]
fn idle_redraw_gate_draws_initial_frame_once_then_waits_for_wake() {
    let mut needs_redraw = true;
    reset_event_loop_draw_call_count();

    if take_redraw_request(&mut needs_redraw) {
        EVENT_LOOP_DRAW_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    assert_eq!(event_loop_draw_call_count(), 1);

    if take_redraw_request(&mut needs_redraw) {
        EVENT_LOOP_DRAW_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
    }
    assert_eq!(
        event_loop_draw_call_count(),
        1,
        "an idle loop pass without a wake must not redraw"
    );
}
