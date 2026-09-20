//! Mouse-only agent authoring through Subagents → Review → Create (#432).
//!
//! The isolated home is seeded to the agent onboarding stage with a loopback
//! provider and machine-bound vault; the PTY child still cold-boots its daemon
//! but should mount agent authoring immediately. Keyboard is not used inside
//! the nested editor walk.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::support::{
    CellPos, HermeticCockpit, HermeticProfile, INITIAL_PTY_COLS, INITIAL_PTY_ROWS, sgr_left_click,
};

const COLD_BOOT_TIMEOUT: Duration = Duration::from_secs(120);
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(30);
const AGENT_ASYNC_TIMEOUT: Duration = Duration::from_secs(120);

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
    std::thread::sleep(Duration::from_millis(150));
    click_text(session, needle);
}

fn mouse_through_agent_authoring(session: &mut HermeticCockpit) {
    click_text(session, "[ Continue ]");
    session
        .wait_until_screen("agent model grants", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Choose the agent's models")
        })
        .expect("name advance reaches model grants");

    click_text(session, "[ Continue ]");
    session
        .wait_until_screen("agent model trust", TRANSITION_TIMEOUT, |screen| {
            screen.contains("How much does this agent see?")
        })
        .expect("model grants advance reaches trust");

    click_text_twice(session, "Confirm vendor/exact-a");
    click_text(session, "[ Continue ]");
    session
        .wait_until_screen("agent optimizations", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Tune the agent")
        })
        .expect("trust advance reaches optimizations");

    click_text(session, "[ Continue ]");
    session
        .wait_until_screen("agent tools", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Grant tools")
        })
        .expect("optimizations advance reaches tools");

    click_text(session, "[ Continue ]");
    session
        .wait_until_screen("agent subagents list", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Define subagents")
                && screen.contains("runner")
                && screen.contains("Review agent package")
        })
        .expect("tools advance reaches subagents with seeded runner");

    click_text(session, "[ Continue ]");
    session
        .wait_until_screen("agent review preview", AGENT_ASYNC_TIMEOUT, |screen| {
            screen.contains("Ready to create") && screen.contains("Summary")
        })
        .expect("preview RPC settles on the review screen");

    click_text(session, "[ Create agent ]");
    session
        .wait_until_screen("agent create confirmation", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Create your agent")
        })
        .expect("review advance reaches create");

    click_text(session, "[ Create agent ]");
    session
        .wait_until_screen("agent authoring success", AGENT_ASYNC_TIMEOUT, |screen| {
            screen.contains("Your agent is ready") || screen.contains("step 7/8")
        })
        .expect("apply RPC commits the authored package");
}

fn find_runner_subagent_package(data_home: &Path) -> Option<PathBuf> {
    let agents_root = data_home.join("cockpit/agents");
    if !agents_root.is_dir() {
        return None;
    }
    fn walk(dir: &Path) -> Option<PathBuf> {
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(found) = walk(&path) {
                    return Some(found);
                }
            } else if path.file_name() == Some(std::ffi::OsStr::new("runner.md"))
                && path.parent().is_some_and(|parent| {
                    parent.file_name() == Some(std::ffi::OsStr::new("subagents"))
                })
            {
                return Some(path);
            }
        }
        None
    }
    walk(&agents_root)
}

#[test]
fn tui_pty_mouse_agent_authoring_keeps_runner_subagent() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake provider");
    let provider_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let provider = std::thread::spawn(move || {
        let body = r#"{"data":[{"id":"scripted","object":"model"}],"object":"list"}"#;
        for _ in 0..16 {
            let Ok((mut socket, _)) = listener.accept() else {
                break;
            };
            socket.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut request = [0_u8; 4096];
            let _ = socket.read(&mut request);
            let _ = write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
        }
    });

    let mut session = HermeticCockpit::prepare_fresh(HermeticProfile::Default);
    session.home().seed_onboarding_open_at_agent(&provider_url);
    session.set_extra_env("COCKPIT_REDUCE_MOTION", "1");
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn cold first-run PTY child");

    session
        .wait_until_screen("agent authoring stage", COLD_BOOT_TIMEOUT, |screen| {
            screen.contains("step 6/8") && screen.contains("Create your first agent")
        })
        .expect("seeded onboarding opens agent authoring in the PTY child");

    mouse_through_agent_authoring(&mut session);

    let runner =
        find_runner_subagent_package(session.home().xdg_data_home()).unwrap_or_else(|| {
            panic!(
                "committed agent package must include subagents/runner.md under {:?}",
                session.home().xdg_data_home().join("cockpit/agents")
            )
        });
    let markdown = std::fs::read_to_string(&runner).expect("read runner subagent markdown");
    assert!(
        markdown.contains("runner"),
        "runner subagent markdown must survive mouse-only authoring: {markdown}"
    );

    provider.join().expect("fake provider thread");
    session.reap();
    session.stop_child_spawned_daemon();
    session.assert_reaped();
}
