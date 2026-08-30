use super::should_attempt_display_attach;
use std::cell::Cell;

/// The happy path: no runner, believed connected, and the daemon answers → attach.
#[test]
fn attaches_when_daemon_reachable() {
    assert!(should_attempt_display_attach(false, true, || true));
}

/// A runner already exists → no attach, and the probe is never run
/// (cheap struct gates short-circuit before the costly probe).
#[test]
fn skips_when_runner_exists_without_probing() {
    let probed = Cell::new(false);
    let attach = should_attempt_display_attach(true, true, || {
        probed.set(true);
        true
    });
    assert!(!attach);
    assert!(!probed.get(), "must not probe once a runner exists");
}

/// `daemon_connected` is false → no attach, no probe.
#[test]
fn skips_when_not_connected() {
    let probed = Cell::new(false);
    let attach = should_attempt_display_attach(false, false, || {
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
    assert!(!should_attempt_display_attach(false, true, || false));
}
