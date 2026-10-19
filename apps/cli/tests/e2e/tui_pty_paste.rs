use std::time::{Duration, Instant};

use crate::support::{
    COMPOSER_PLACEHOLDER, HermeticCockpit, HermeticLaunchKind, HermeticProfile,
    fragmented_bracketed_paste, pid_is_live,
};

#[test]
fn tui_pty_bracketed_paste_protocol() {
    let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
    assert!(
        session.snapshot().contains(COMPOSER_PLACEHOLDER),
        "ready composer required before paste"
    );

    let payload = "pty-paste-literal-xyz";
    for frame in fragmented_bracketed_paste(&["pty-paste-", "literal-xyz"]) {
        session.write_bytes(&frame);
    }

    session
        .wait_until_screen(
            "reconstructed literal paste in composer",
            Duration::from_secs(5),
            |screen| screen.contains(payload),
        )
        .expect("bracketed paste reconstructed");
    let contents = session.snapshot().contents();
    assert!(
        contents.contains(payload),
        "composer must show the reconstructed literal payload:\n{contents}"
    );
    assert_eq!(
        contents.matches(payload).count(),
        1,
        "payload must appear once before submit:\n{contents}"
    );
}

#[test]
fn tui_pty_bracketed_paste_keeps_lines_and_indentation() {
    for newline in ["\r", "\n", "\r\n"] {
        let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
        // Both tmux and native-terminal line endings cross the real parser.
        for frame in fragmented_bracketed_paste(&["def item():", newline, "\treturn 1"]) {
            session.write_bytes(&frame);
        }
        session
            .wait_until_screen(
                "multiline indented paste",
                Duration::from_secs(5),
                |screen| screen.contains("def item():") && screen.contains("    return 1"),
            )
            .expect("paste must keep its newline and tab indentation");
        let screen = session.settled_snapshot();
        let head = screen.find_text("def item():").unwrap();
        let body = screen.find_text("return 1").unwrap();
        assert_eq!(
            body.row,
            head.row + 1,
            "pasted newline is a visual line break"
        );
        assert_eq!(body.col, head.col + 4, "tab occupies four editor cells");
    }
}

#[test]
fn tui_pty_idle_quit_and_ctrl_c_exit_promptly() {
    for input in [b"/quit\r".as_slice(), b"\x03".as_slice()] {
        for attached in [false, true] {
            let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
            if attached {
                session.materialize_session("composer quit fixture");
                session
                    .wait_until_screen(
                        "idle attached composer",
                        Duration::from_secs(10),
                        |screen| screen.contains(COMPOSER_PLACEHOLDER),
                    )
                    .expect("attached turn settles before idle quit");
            }
            let daemon = session
                .daemon_pid()
                .expect("fixture owns a persistent daemon");
            let started = Instant::now();
            session.write_bytes(input);
            assert_eq!(
                session.wait_for_child_exit_status(),
                Some(true),
                "quit must succeed"
            );
            let elapsed = started.elapsed();
            eprintln!("idle quit attached={attached} input={input:?}: {elapsed:?}");
            assert!(
                elapsed <= Duration::from_millis(1500),
                "idle quit exceeded ~1s: {elapsed:?}"
            );
            assert!(
                pid_is_live(daemon),
                "quitting the TUI must preserve the shared daemon"
            );
        }
    }
}

#[test]
fn tui_pty_rename_argument_renames_durable_session() {
    let mut session = HermeticCockpit::launch_ready(HermeticProfile::Default);
    session.write_str("/hlep");
    session
        .wait_until_screen("unknown text composed", Duration::from_secs(5), |screen| {
            screen.contains("/hlep")
        })
        .unwrap();
    session.send_enter();
    session
        .wait_until_screen(
            "unknown command feedback with text retained",
            Duration::from_secs(5),
            |screen| screen.contains("Unknown slash command") && screen.contains("/hlep"),
        )
        .expect("unknown slash must explain and preserve text");
    assert!(
        session.settled_snapshot().contains("Draft (unsaved)"),
        "feedback must not materialize a session"
    );
    session.send_enter();
    session
        .wait_until_attached(Duration::from_secs(30))
        .expect("literal unknown slash can create a session");
    session
        .wait_until_screen("literal slash sent", Duration::from_secs(10), |screen| {
            screen.contains("/hlep") && screen.contains(COMPOSER_PLACEHOLDER)
        })
        .unwrap();
    // Like materialize_session, separate composition from Enter: a raw PTY
    // burst including Enter is intentionally classified as rapid paste.
    session.write_str("/rename Composer Contract Title");
    session
        .wait_until_screen(
            "rename argument composed",
            Duration::from_secs(5),
            |screen| screen.contains("/rename Composer Contract Title"),
        )
        .unwrap();
    session.send_enter();
    session
        .wait_until_screen("rename acknowledgement", Duration::from_secs(5), |screen| {
            screen.contains("Renamed session to `Composer Contract Title`")
        })
        .expect("argument-bearing rename must rename, without opening provider setup");
    assert!(
        !session.settled_snapshot().contains("[Close settings]"),
        "rename must not open provider settings"
    );
    let mut path = session.spec().launch_path(HermeticLaunchKind::DaemonStatus);
    path.args = vec!["session".into(), "list".into()];
    let output = path
        .std_command()
        .output()
        .expect("list durable sessions through CLI RPC");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Composer Contract Title"),
        "rename must reach the durable session through the daemon"
    );
}
