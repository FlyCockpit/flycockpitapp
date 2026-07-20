use super::{App, ToastKind};
use cockpit_core::engine::TurnEvent;

fn apply_caffeinate(app: &mut App, active: bool, lid_close_guaranteed: bool, message: &str) {
    app.apply_event(TurnEvent::CaffeinateState {
        active,
        lid_close_guaranteed,
        message: Some(message.to_string()),
    });
}

#[test]
fn active_caffeinate_lid_caveat_uses_warning_toast() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    apply_caffeinate(
        &mut app,
        true,
        false,
        "caffeinate on - lid-close not guaranteed",
    );

    assert!(app.caffeinate_active);
    let toast = app.toast.as_ref().expect("toast shown");
    assert_eq!(toast.kind, ToastKind::Warning);
    assert!(toast.text.contains("lid-close"));
}

#[test]
fn active_caffeinate_without_caveat_uses_info_toast() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    apply_caffeinate(&mut app, true, true, "caffeinate on");

    assert!(app.caffeinate_active);
    assert!(matches!(
        app.toast.as_ref(),
        Some(toast) if toast.kind == ToastKind::Info && toast.text == "caffeinate on"
    ));
}

#[test]
fn inactive_caffeinate_state_stays_info_toast() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.caffeinate_active = true;

    apply_caffeinate(&mut app, false, false, "caffeinate off");

    assert!(!app.caffeinate_active);
    assert!(matches!(
        app.toast.as_ref(),
        Some(toast) if toast.kind == ToastKind::Info && toast.text == "caffeinate off"
    ));
}
