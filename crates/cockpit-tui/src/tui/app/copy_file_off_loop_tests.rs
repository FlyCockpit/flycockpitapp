//! AC5 (tui-copy-command-file-output): copy_command_file_off_loop_generation
//! — `/copy … file` runs off the event loop (`start_copy_to_file_action`
//! returns immediately, before any disk I/O has necessarily completed) and
//! a late result from a superseded request can never notify a since-changed
//! view.

use super::{App, CopyFormat};
use crate::tui::async_action::{
    AsyncActionId, AsyncActionKind, AsyncActionPayload, AsyncActionResult,
};

async fn drain_until_idle(app: &mut App) {
    for _ in 0..200 {
        tokio::task::yield_now().await;
        app.drain_async_actions();
        if app.async_actions.pending_count() == 0 {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("copy.file action did not complete");
}

#[tokio::test]
async fn starting_the_action_returns_immediately_without_blocking() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let target = tmp.path().join("out.md");

    let start = std::time::Instant::now();
    app.start_copy_to_file_action(
        target.display().to_string(),
        CopyFormat::Markdown,
        "hello".to_string(),
    );
    // `start_blocking` hands the work to `spawn_blocking` and returns
    // synchronously; this call must not itself perform the file I/O.
    assert!(
        start.elapsed() < std::time::Duration::from_millis(500),
        "start_copy_to_file_action must not block on the write"
    );
    assert_eq!(app.async_actions.pending_count(), 1);

    drain_until_idle(&mut app).await;
    assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    let toast = app.toast.as_ref().expect("success toast shown");
    assert!(toast.text.contains("Wrote"));
}

#[tokio::test]
async fn a_second_request_replaces_the_first_and_only_its_result_surfaces() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let target1 = tmp.path().join("first.md");
    let target2 = tmp.path().join("second.md");

    app.start_copy_to_file_action(
        target1.display().to_string(),
        CopyFormat::Markdown,
        "first payload".to_string(),
    );
    let first_id = app
        .async_actions
        .pending_ids()
        .first()
        .copied()
        .expect("first action pending");

    // A second `/copy … file` before the first finishes replaces it
    // (`AsyncActionPolicy::Replace`), not runs alongside it — never two
    // pending `copy.file` actions at once.
    app.start_copy_to_file_action(
        target2.display().to_string(),
        CopyFormat::Markdown,
        "second payload".to_string(),
    );
    assert_eq!(
        app.async_actions.pending_count(),
        1,
        "the second request replaces the first, not runs alongside it"
    );
    let second_id = app
        .async_actions
        .pending_ids()
        .first()
        .copied()
        .expect("second action pending");
    assert_ne!(first_id, second_id);

    // The first request's blocking write may still run to completion on
    // its background thread (a `spawn_blocking` abort cannot interrupt
    // work already in flight) — but by the time it reports in, its
    // `pending` bookkeeping is gone (replaced above), so
    // `AsyncActionRunner::drain_completed` discards that message on its
    // own: a late result from a superseded request never reaches a toast.
    drain_until_idle(&mut app).await;

    let toast = app.toast.as_ref().expect("second result must surface");
    assert!(toast.text.contains("second.md"), "{}", toast.text);
    assert!(!toast.text.contains("first.md"), "{}", toast.text);
}

#[tokio::test]
async fn a_second_request_signals_real_cancellation_to_the_first() {
    // M7: a superseding request must not just let the first request's
    // publish run to completion unnoticed — it must actually flip that
    // request's cancellation flag, so the first publish can abandon at its
    // checkpoint before ever touching its target name.
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    app.start_copy_to_file_action(
        tmp.path().join("first.md").display().to_string(),
        CopyFormat::Markdown,
        "first payload".to_string(),
    );
    let first_flag = app
        .copy_file_cancel
        .clone()
        .expect("first action recorded a cancellation flag");
    assert!(
        !first_flag.load(std::sync::atomic::Ordering::Relaxed),
        "not cancelled yet"
    );

    app.start_copy_to_file_action(
        tmp.path().join("second.md").display().to_string(),
        CopyFormat::Markdown,
        "second payload".to_string(),
    );
    assert!(
        first_flag.load(std::sync::atomic::Ordering::Relaxed),
        "starting a second `/copy … file` must cancel the first"
    );
    let second_flag = app
        .copy_file_cancel
        .clone()
        .expect("second action recorded its own cancellation flag");
    assert!(
        !std::sync::Arc::ptr_eq(&first_flag, &second_flag),
        "the second request gets its own fresh flag, not the first's"
    );
    assert!(
        !second_flag.load(std::sync::atomic::Ordering::Relaxed),
        "the second (current) request is not itself cancelled"
    );

    drain_until_idle(&mut app).await;
}

fn any_pending_action_id(app: &mut App, target: &std::path::Path) -> AsyncActionId {
    // `apply_async_action_result` does not itself validate `id` against
    // anything (that bookkeeping lives in `AsyncActionRunner::drain_completed`,
    // which these tests intentionally bypass), but `AsyncActionId`'s inner
    // field is private, so a real one is obtained the only way available:
    // starting a real action and reading it back. `target` must live inside
    // the test's own tempdir — this really does spawn a background write.
    app.start_copy_to_file_action(
        target.display().to_string(),
        CopyFormat::Markdown,
        "probe".to_string(),
    );
    app.async_actions
        .pending_ids()
        .first()
        .copied()
        .expect("an action was just started")
}

#[tokio::test]
async fn durability_confirmed_publish_shows_an_ordinary_success_toast() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let id = any_pending_action_id(&mut app, &tmp.path().join("durability-probe.md"));

    app.apply_async_action_result(AsyncActionResult {
        id,
        kind: AsyncActionKind::Blocking("copy.file"),
        presentation_stale: false,
        payload: Ok(AsyncActionPayload::CopyToFile {
            path: "/tmp/out.md".into(),
            bytes_written: 5,
            durability_confirmed: true,
        }),
    });

    let toast = app.toast.as_ref().expect("toast shown");
    assert_eq!(toast.kind, crate::tui::app::ToastKind::Success);
    assert!(toast.text.contains("Wrote 5 bytes"));
    assert!(!toast.text.to_lowercase().contains("unconfirmed"));

    // Drain the real background write so nothing dangles past the test.
    drain_until_idle(&mut app).await;
}

#[tokio::test]
async fn durability_unconfirmed_publish_shows_a_distinct_warning_never_a_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let id = any_pending_action_id(&mut app, &tmp.path().join("durability-probe.md"));

    app.apply_async_action_result(AsyncActionResult {
        id,
        kind: AsyncActionKind::Blocking("copy.file"),
        presentation_stale: false,
        payload: Ok(AsyncActionPayload::CopyToFile {
            path: "/tmp/out.md".into(),
            bytes_written: 5,
            durability_confirmed: false,
        }),
    });

    let toast = app.toast.as_ref().expect("toast shown");
    // The file is genuinely on disk: this must never be styled or worded
    // as a failure (the HIGH finding this proves against), and must be
    // visibly distinct from the ordinary-success wording above.
    assert_ne!(toast.kind, crate::tui::app::ToastKind::Error);
    assert_eq!(toast.kind, crate::tui::app::ToastKind::Warning);
    assert!(toast.text.contains("Wrote 5 bytes"));
    assert!(toast.text.to_lowercase().contains("unconfirmed"));

    drain_until_idle(&mut app).await;
}

#[test]
fn payload_over_cap_is_rejected_synchronously_without_starting_an_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let oversized = "x".repeat(crate::clipboard::file_publish::MAX_PAYLOAD_BYTES + 1);
    app.start_copy_to_file_action("/tmp/out.md".to_string(), CopyFormat::Markdown, oversized);
    assert_eq!(
        app.async_actions.pending_count(),
        0,
        "an over-cap payload must never reach the async runner"
    );
    let toast = app.toast.as_ref().expect("over-cap toast shown");
    assert!(toast.text.contains("too large"));
}
