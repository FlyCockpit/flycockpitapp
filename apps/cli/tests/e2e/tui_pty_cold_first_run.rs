//! Cold first-run onboarding over a real PTY (#425).
//!
//! Unlike the configured-installation fixtures, this scenario starts from
//! `IsolatedHome::new_fresh()`: no database, no onboarding authority, no
//! provider config, and no pre-started daemon. The PTY child's TUI must
//! spawn the daemon itself, present the Welcome shell, and advance to the
//! Profile stage with a single keystroke — the exact path that used to
//! wedge silently at step 1.

use std::time::Duration;

use crate::support::{
    CellPos, HermeticCockpit, HermeticProfile, INITIAL_PTY_COLS, INITIAL_PTY_ROWS, sgr_left_click,
};

/// Cold boot (daemon spawn + DB creation) is slower than the configured
/// recipe; keep the Welcome budget generous.
const COLD_WELCOME_TIMEOUT: Duration = Duration::from_secs(120);
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(30);

fn click_text(session: &mut HermeticCockpit, needle: &str) {
    let snapshot = session.snapshot();
    let (start, end) = snapshot
        .find_text_span(needle)
        .unwrap_or_else(|| panic!("expected `{needle}` on screen:\n{}", snapshot.contents()));
    let pos = CellPos {
        row: start.row,
        col: (start.col + end.col) / 2,
    };
    session.write_bytes(&sgr_left_click(pos.sgr_x(), pos.sgr_y()));
}

fn click_text_twice(session: &mut HermeticCockpit, needle: &str) {
    click_text(session, needle);
    session.checkpoint_input_with_redraw();
    click_text(session, needle);
}

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
            |screen| {
                screen.contains("[press any button to continue]")
                    || screen.contains("Onboarding authority unavailable:")
            },
        )
        .expect("cold first-run resolves onboarding bootstrap");
    let welcome = session.snapshot().contents();
    assert!(
        welcome.contains("[press any button to continue]"),
        "cold first-run must reach the settled Welcome prompt:\n{welcome}"
    );
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
        "the Profile stage must present its native shell screen:\n{profile}"
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

/// Mouse-only walkthrough Welcome → Provider catalog (#429). Keyboard input
/// is used only to type the optional profile name.
#[test]
fn tui_pty_cold_first_run_mouse_walkthrough_to_provider_catalog() {
    let mut session = HermeticCockpit::prepare_fresh(HermeticProfile::Default);
    session.set_extra_env("COCKPIT_REDUCE_MOTION", "1");
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn cold first-run PTY child");

    session
        .wait_until_screen(
            "cold first-run Welcome shell",
            COLD_WELCOME_TIMEOUT,
            |screen| {
                screen.contains("[press any button to continue]")
                    || screen.contains("Onboarding authority unavailable:")
            },
        )
        .expect("cold first-run resolves onboarding bootstrap");
    let welcome = session.snapshot().contents();
    assert!(
        welcome.contains("[press any button to continue]"),
        "cold first-run must reach the settled Welcome prompt:\n{welcome}"
    );

    click_text(&mut session, "[press any button to continue]");
    session
        .wait_until_screen(
            "Profile stage after Welcome click",
            TRANSITION_TIMEOUT,
            |screen| {
                screen.contains("step 2/8") && screen.contains("What should Cockpit call you?")
            },
        )
        .expect("Welcome pointer advance reaches Profile");

    session.write_str("Ada");
    click_text(&mut session, "[ Continue ]");
    session
        .wait_until_screen(
            "Secure store after profile save",
            TRANSITION_TIMEOUT,
            |screen| screen.contains("step 3/8") && screen.contains("Secure your secrets"),
        )
        .expect("Profile Continue reaches Secure store");

    click_text_twice(&mut session, "Machine-bound encrypted file");
    session
        .wait_until_screen(
            "Provider catalog after secure-store choice",
            TRANSITION_TIMEOUT,
            |screen| {
                screen.contains("step 4/8")
                    && screen.contains("Let's add a provider")
                    && screen.contains("Providers")
            },
        )
        .expect("secure-store pointer choice reaches the provider catalog");
    let provider = session.snapshot().contents();
    assert!(provider.contains("Filter"), "{provider}");
    assert!(provider.contains("filter by name"), "{provider}");
    assert!(
        !provider.contains("Choose workspace trust:"),
        "workspace resolution must stay deferred while onboarding is open:\n{provider}"
    );

    session.reap();
    session.stop_child_spawned_daemon();
    session.assert_reaped();
}
