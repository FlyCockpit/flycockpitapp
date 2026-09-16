//! Cold first-run onboarding over a real PTY (#425).
//!
//! Unlike the configured-installation fixtures, this scenario starts from
//! `IsolatedHome::new_fresh()`: no database, no onboarding authority, no
//! provider config, and no pre-started daemon. The PTY child's TUI must
//! spawn the daemon itself, present the Welcome shell, and advance to the
//! Profile stage with a single keystroke — the exact path that used to
//! wedge silently at step 1.

use std::time::Duration;

use crate::support::{HermeticCockpit, HermeticProfile, INITIAL_PTY_COLS, INITIAL_PTY_ROWS};

/// Cold boot (daemon spawn + DB creation) is slower than the configured
/// recipe; keep the Welcome budget generous.
const COLD_WELCOME_TIMEOUT: Duration = Duration::from_secs(120);
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(30);

#[test]
fn tui_pty_cold_first_run_advances_from_welcome_with_one_key() {
    let mut session = HermeticCockpit::prepare_fresh(HermeticProfile::Default);
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn cold first-run PTY child");

    // The TUI must spawn its own daemon and land on the Welcome shell —
    // never on the workspace-trust modal or a composer.
    session
        .wait_until_screen(
            "cold first-run Welcome shell",
            COLD_WELCOME_TIMEOUT,
            |screen| screen.contains("Cockpit setup") && screen.contains("step 1/8"),
        )
        .expect("cold first-run reaches Welcome");
    let welcome = session.snapshot().contents();
    assert!(welcome.contains("Welcome"), "{welcome}");
    assert!(
        !welcome.contains("Choose workspace trust:"),
        "workspace resolution must stay deferred while onboarding is open:\n{welcome}"
    );
    assert!(
        !welcome.contains("bootstrap is locked"),
        "the locked bootstrap path must not surface as a first-run error:\n{welcome}"
    );
    assert!(
        session.socket_path().exists(),
        "the cold run must be talking to a TUI-spawned daemon at {}",
        session.socket_path().display()
    );

    // One key — the exact input the wedge used to swallow.
    session.send_enter();

    session
        .wait_until_screen(
            "Profile stage after one key",
            TRANSITION_TIMEOUT,
            |screen| screen.contains("step 2/8"),
        )
        .expect("one keystroke advances Welcome to the Profile stage");
    let profile = session.snapshot().contents();
    assert!(
        profile.contains("What should Cockpit call you?"),
        "the Profile stage must present its own wizard engine:\n{profile}"
    );
    assert!(
        !profile.contains("could not be applied"),
        "the transition must apply without a correlation error toast:\n{profile}"
    );
    assert!(
        !profile.contains("Choose workspace trust:"),
        "workspace resolution must stay deferred while onboarding is open:\n{profile}"
    );

    // Cleanup: reap() only owns fixture-started daemons, and the locked
    // bootstrap matrix has no stop verb (#426), so the PTY-spawned daemon
    // is stopped through the receipt-verified process stop.
    session.reap();
    session.stop_child_spawned_daemon();
    session.assert_reaped();
}
