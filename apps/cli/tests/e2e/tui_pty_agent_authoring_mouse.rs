//! Mouse-only agent authoring through Subagents → Review → Create (#432).
//!
//! The isolated home is seeded to the agent onboarding stage with a loopback
//! provider and machine-bound vault; the PTY child still cold-boots its daemon
//! but should mount agent authoring immediately. Keyboard is not used inside
//! the nested editor walk.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::support::{
    CellPos, HermeticCockpit, HermeticProfile, INITIAL_PTY_COLS, INITIAL_PTY_ROWS, sgr_left_click,
};

const COLD_BOOT_TIMEOUT: Duration = Duration::from_secs(90);
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(30);
const AGENT_ASYNC_TIMEOUT: Duration = Duration::from_secs(90);
const RUNNER_ARTIFACT_TIMEOUT: Duration = Duration::from_secs(90);

fn spawn_loopback_models_provider() -> (String, Arc<AtomicBool>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake provider");
    listener
        .set_nonblocking(true)
        .expect("nonblocking provider");
    let provider_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = Arc::clone(&shutdown);
    std::thread::spawn(move || {
        let body = r#"{"data":[{"id":"scripted","object":"model"}],"object":"list"}"#;
        while !shutdown_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut socket, _)) => {
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
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    (provider_url, shutdown)
}

fn unset_trust_confirm_label(screen: &str) -> String {
    const PREFIX: &str = "Confirm ";
    const SUFFIX: &str = " as unset";
    for line in screen.lines() {
        let Some(start) = line.find(PREFIX) else {
            continue;
        };
        let rest = &line[start..];
        let Some(end) = rest.find(SUFFIX) else {
            continue;
        };
        return rest[..end + SUFFIX.len()].to_string();
    }
    panic!("expected unset trust confirm row on screen:\n{screen}");
}

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

fn mouse_confirm_runner_subagent_trust(session: &mut HermeticCockpit) {
    click_text(session, "▸ runner");
    session
        .wait_until_screen("runner subagent identity", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Subagent") && screen.contains("runner")
        })
        .expect("runner row opens the nested editor");

    click_text(session, "[ Continue ]");
    session
        .wait_until_screen("runner model grants", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Subagent models")
        })
        .expect("runner identity advance reaches model grants");

    // #486: grants advance to trust only while an enabled route is unset;
    // either way the nested editor then shows the subagent Optimizations
    // step ("Tune the subagent") before tool tiers.
    click_text(session, "[ Continue ]");
    session
        .wait_until_screen(
            "runner model trust or optimizations",
            TRANSITION_TIMEOUT,
            |screen| {
                screen.contains("How much does this subagent see?")
                    || screen.contains("Tune the subagent")
            },
        )
        .expect(
            "runner grants advance reaches trust or skips its pre-confirmed safe route to optimizations",
        );
    if session
        .snapshot()
        .contains("How much does this subagent see?")
    {
        let trust_row = unset_trust_confirm_label(&session.snapshot().contents());
        click_text_twice(session, &trust_row);
        click_text(session, "[ Continue ]");
        session
            .wait_until_screen("runner optimizations", TRANSITION_TIMEOUT, |screen| {
                screen.contains("Tune the subagent")
            })
            .expect("runner trust advance reaches optimizations");
    }

    click_text(session, "[ Continue ]");
    session
        .wait_until_screen("runner tool tiers", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Subagent tools")
        })
        .expect("runner optimizations advance reaches tools");

    click_text(session, "[ Continue ]");
    session
        .wait_until_screen("runner nested subagents", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Subagent helpers")
        })
        .expect("runner tools advance reaches nested subagents list");

    click_text(session, "[ Save ]");
    session
        .wait_until_screen(
            "runner saved to subagents list",
            TRANSITION_TIMEOUT,
            |screen| screen.contains("Define subagents") && screen.contains("runner"),
        )
        .expect("runner trust confirmation persists on the list");
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

    let trust_row = unset_trust_confirm_label(&session.snapshot().contents());
    click_text_twice(session, &trust_row);
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

    mouse_confirm_runner_subagent_trust(session);

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
        .wait_until_screen("agent package committed", AGENT_ASYNC_TIMEOUT, |screen| {
            screen.contains("Background agents") && screen.contains("step 7/8")
        })
        .expect("committed agent package advances onboarding to the Lifetime stage");
}

fn find_runner_subagent_package(agents_root: &Path) -> Option<PathBuf> {
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
    walk(agents_root)
}

#[test]
fn tui_pty_mouse_agent_authoring_keeps_runner_subagent() {
    let (provider_url, provider_shutdown) = spawn_loopback_models_provider();

    let mut session = HermeticCockpit::prepare_fresh(HermeticProfile::Default);
    session.home().seed_onboarding_open_at_agent(&provider_url);
    session.enable_isolated_secret_service();
    session.start_detached_daemon();
    session.home().set_workspace_trust_via_daemon();
    session.set_extra_env("COCKPIT_REDUCE_MOTION", "1");
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn agent-authoring PTY child against pre-started daemon");

    session
        .wait_until_screen("agent authoring stage", COLD_BOOT_TIMEOUT, |screen| {
            screen.contains("step 6/8") && screen.contains("Create your first agent")
        })
        .expect("seeded onboarding opens agent authoring in the PTY child");

    session.home().set_workspace_trust_via_daemon();

    mouse_through_agent_authoring(&mut session);
    let agents_root = session.home().daemon_agents_dir();
    let runner_deadline = Instant::now() + RUNNER_ARTIFACT_TIMEOUT;
    let mut runner_delay = Duration::from_millis(20);
    let runner = loop {
        if let Some(path) = find_runner_subagent_package(&agents_root) {
            break path;
        }
        if Instant::now() >= runner_deadline {
            panic!(
                "committed agent package must include subagents/runner.md under {agents_root:?}"
            );
        }
        std::thread::sleep(runner_delay);
        runner_delay = (runner_delay * 2).min(Duration::from_millis(200));
    };
    let markdown = std::fs::read_to_string(&runner).expect("read runner subagent markdown");
    assert!(
        markdown.contains("runner"),
        "runner subagent markdown must survive mouse-only authoring: {markdown}"
    );

    provider_shutdown.store(true, Ordering::Relaxed);
    session.stop_child_spawned_daemon();
    session.forget_fixture_daemon_ownership();
    session.reap();
    session.assert_reaped();
}
