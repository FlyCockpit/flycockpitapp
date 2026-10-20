use super::{
    EVENT_LOOP_DRAW_CALL_COUNT, event_loop_draw_call_count, reset_event_loop_draw_call_count,
    take_redraw_request,
};
use std::sync::atomic::Ordering;

use super::{ANIMATION_TICK, App};
use crate::tui::input_source::TerminalInput;
use crossterm::event::{Event, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::backend::{CrosstermBackend, TestBackend};
use ratatui::{Terminal, TerminalOptions, Viewport};
use std::sync::Arc;

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

fn welcome_buffer(app: &mut App) -> ratatui::buffer::Buffer {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal
        .draw(|frame| {
            app.onboarding_shell.as_mut().unwrap().render(
                frame,
                frame.area(),
                &app.dialog,
                &mut app.link_registry,
            );
        })
        .unwrap();
    terminal.backend().buffer().clone()
}

#[tokio::test(start_paused = true)]
async fn welcome_event_loop_wakes_follow_time_through_idle_and_mouse_bursts() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at_async(tmp.path()).await;
    let mut app = App::new(Some(tmp.path()), false);
    app.onboarding_shell = Some(Box::new(super::golden::onboarding_welcome_shell_at(
        0, false,
    )));
    // The wake service does not draw. A fixed viewport avoids terminal queries
    // while exercising the production service with its normal backend type.
    let mut terminal = Terminal::with_options(
        CrosstermBackend::new(std::io::stdout()),
        TerminalOptions {
            viewport: Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 80, 24)),
        },
    )
    .unwrap();
    let origin = tokio::time::Instant::now();
    let mut input = TerminalInput::new_for_test_events(
        Arc::new(move || origin.elapsed()),
        (0..1_000).map(|_| {
            Ok(Event::Mouse(MouseEvent {
                kind: MouseEventKind::Moved,
                column: 40,
                row: 12,
                modifiers: KeyModifiers::NONE,
            }))
        }),
    );
    app.first_paint_completed = true;
    app.service_event_loop_wake(&mut terminal, &mut input)
        .await
        .unwrap();
    for frame in 0..=crate::tui::onboarding::WELCOME_ANIMATION_FRAMES + 4 {
        if frame > 0 {
            assert!(app.animation_tick_active());
            tokio::time::sleep(ANIMATION_TICK).await;
            app.service_event_loop_wake(&mut terminal, &mut input)
                .await
                .unwrap();
        }
        // Both fly-in and landed motion must ignore a burst at one instant.
        if frame == 0 || frame == crate::tui::onboarding::WELCOME_ANIMATION_FRAMES {
            for _ in 0..500 {
                let event = input.next().await;
                assert!(!app.handle_event_stream_item(event).unwrap());
                app.service_event_loop_wake(&mut terminal, &mut input)
                    .await
                    .unwrap();
            }
        }
        assert_eq!(
            welcome_buffer(&mut app),
            super::golden::render_onboarding_welcome_at(80, 24, frame, false),
            "wake service must render the elapsed frame {frame}"
        );
    }
    assert!(
        app.animation_tick_active(),
        "ambient motion must stay active"
    );
}
