use super::should_attempt_display_attach;
use std::cell::Cell;

/// The happy path: no runner, prompt closed, not daemonless, believed
/// connected, and the daemon answers → attach.
#[test]
fn attaches_when_daemon_reachable() {
    assert!(should_attempt_display_attach(
        false,
        false,
        false,
        true,
        || true
    ));
}

/// A runner already exists → no attach, and the probe is never run
/// (cheap struct gates short-circuit before the costly probe).
#[test]
fn skips_when_runner_exists_without_probing() {
    let probed = Cell::new(false);
    let attach = should_attempt_display_attach(true, false, false, true, || {
        probed.set(true);
        true
    });
    assert!(!attach);
    assert!(!probed.get(), "must not probe once a runner exists");
}

/// The "daemon not running" prompt is still open → don't spawn a daemon
/// out from under the user's choice; probe is skipped.
#[test]
fn skips_while_prompt_open() {
    let probed = Cell::new(false);
    let attach = should_attempt_display_attach(false, true, false, true, || {
        probed.set(true);
        true
    });
    assert!(!attach);
    assert!(!probed.get());
}

/// Daemonless ("continue without daemon") → never eager-spawn the owned
/// ephemeral daemon purely to display an id (deliberate non-goal). Probe
/// is skipped even though `daemon_connected` is true in this mode.
#[test]
fn skips_in_daemonless_mode() {
    let probed = Cell::new(false);
    let attach = should_attempt_display_attach(false, false, true, true, || {
        probed.set(true);
        true
    });
    assert!(!attach);
    assert!(
        !probed.get(),
        "daemonless must not probe/attach for display"
    );
}

/// `daemon_connected` is false → no attach, no probe.
#[test]
fn skips_when_not_connected() {
    let probed = Cell::new(false);
    let attach = should_attempt_display_attach(false, false, false, false, || {
        probed.set(true);
        true
    });
    assert!(!attach);
    assert!(!probed.get());
}

/// All cheap gates pass but the just-started daemon's socket isn't bound
/// yet (probe returns false) → wait quietly; retry on a later tick. This
/// is the "Start and connect" startup gap that previously double-spawned.
#[test]
fn waits_when_socket_not_yet_bound() {
    assert!(!should_attempt_display_attach(
        false,
        false,
        false,
        true,
        || false
    ));
}
