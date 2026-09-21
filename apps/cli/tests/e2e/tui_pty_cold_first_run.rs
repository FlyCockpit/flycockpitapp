//! Cold first-run onboarding over a real PTY (#425).
//!
//! Unlike the configured-installation fixtures, this scenario starts from
//! `IsolatedHome::new_fresh()`: no database, no onboarding authority, no
//! provider config, and no pre-started daemon. The PTY child's TUI must
//! spawn the daemon itself, present the Welcome shell, and advance to the
//! Profile stage with a single keystroke — the exact path that used to
//! wedge silently at step 1.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::support::{
    COMPOSER_PLACEHOLDER, CellPos, HermeticCockpit, HermeticProfile, INITIAL_PTY_COLS,
    INITIAL_PTY_ROWS, sgr_left_click,
};

/// Cold boot (daemon spawn + DB creation) is slower than the configured
/// recipe; keep the Welcome budget generous.
const COLD_WELCOME_TIMEOUT: Duration = Duration::from_secs(120);
const TRANSITION_TIMEOUT: Duration = Duration::from_secs(30);
const ASYNC_STAGE_TIMEOUT: Duration = Duration::from_secs(120);
const DAEMON_STABILITY_WINDOW: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum WalkthroughInput {
    Keyboard,
    Mouse,
}

fn spawn_loopback_models_provider() -> (String, Arc<AtomicBool>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake provider");
    listener
        .set_nonblocking(true)
        .expect("make fake provider nonblocking");
    let provider_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = Arc::clone(&shutdown);
    std::thread::spawn(move || {
        let body = r#"{"data":[{"id":"scripted","object":"model"},{"id":"fallback","object":"model"}],"object":"list"}"#;
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
    let snapshot = session.snapshot();
    let (start, end) = snapshot
        .find_text_span(needle)
        .unwrap_or_else(|| panic!("expected `{needle}` on screen:\n{}", snapshot.contents()));
    let pos = CellPos {
        row: start.row,
        col: (start.col + end.col) / 2,
    };
    let click = sgr_left_click(pos.sgr_x(), pos.sgr_y());
    let mut double_click = click.clone();
    double_click.extend_from_slice(&click);
    session.write_bytes(&double_click);
}

fn activate(session: &mut HermeticCockpit, input: WalkthroughInput, label: &str) {
    match input {
        WalkthroughInput::Keyboard => {
            session.send_enter();
            session.checkpoint_input_with_redraw();
        }
        WalkthroughInput::Mouse => click_text(session, label),
    }
}

fn keyboard_input(session: &mut HermeticCockpit, bytes: &[u8]) {
    session.write_bytes(bytes);
    session.checkpoint_input_with_redraw();
}

fn wait_for_text(session: &mut HermeticCockpit, label: &str, needle: &str) {
    session
        .wait_until_screen(label, ASYNC_STAGE_TIMEOUT, |screen| screen.contains(needle))
        .unwrap_or_else(|error| panic!("{error}"));
}

fn daemon_generation(session: &HermeticCockpit) -> u64 {
    let rendezvous = session.home().pid_file().with_file_name("daemon.json");
    let bytes = std::fs::read(&rendezvous)
        .unwrap_or_else(|error| panic!("read daemon rendezvous {rendezvous:?}: {error}"));
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .expect("decode daemon rendezvous")
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .expect("daemon rendezvous has a numeric generation")
}

fn wait_for_daemon_roll_to_stability(session: &HermeticCockpit, previous_generation: u64) {
    let deadline = Instant::now() + TRANSITION_TIMEOUT;
    let mut observed_generation = previous_generation;
    let mut stable_since = None;
    loop {
        let generation = daemon_generation(session);
        if generation > previous_generation {
            session.wait_for_daemon_handshake(TRANSITION_TIMEOUT);
            if generation != observed_generation {
                observed_generation = generation;
                stable_since = Some(Instant::now());
            }
            if stable_since.is_some_and(|since| since.elapsed() >= DAEMON_STABILITY_WINDOW)
                && daemon_generation(session) == observed_generation
            {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "provider-config publication did not produce a stable daemon worker"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn configure_custom_provider(
    session: &mut HermeticCockpit,
    input: WalkthroughInput,
    provider_url: &str,
) {
    session.write_str("compat");
    match input {
        WalkthroughInput::Keyboard => {
            keyboard_input(session, b"\x1b[B");
            keyboard_input(session, b"\r");
        }
        WalkthroughInput::Mouse => {
            session.checkpoint_input_with_redraw();
            click_text_twice(session, "OpenAI-compatible");
        }
    }
    wait_for_text(
        session,
        "custom provider authentication",
        "Add your API key",
    );

    session.write_str("localtest");
    let generation = daemon_generation(session);
    match input {
        WalkthroughInput::Keyboard => {
            keyboard_input(session, b"\t");
            session.write_str(provider_url);
            keyboard_input(session, b"\t");
            session.write_str("test-key");
            keyboard_input(session, b"\r");
        }
        WalkthroughInput::Mouse => {
            session.checkpoint_input_with_redraw();
            click_text(session, "╭ Base URL");
            session.write_str(provider_url);
            session.checkpoint_input_with_redraw();
            click_text(session, "╭ API key");
            session.write_str("test-key");
            session.checkpoint_input_with_redraw();
            click_text(session, "[ Continue ]");
        }
    }

    wait_for_text(session, "provider verification result", "Connected");
    wait_for_daemon_roll_to_stability(session, generation);
    activate(session, input, "[ Done ]");
    session
        .wait_until_screen("native model screen", ASYNC_STAGE_TIMEOUT, |screen| {
            screen.contains("Choose your default model")
                || screen.contains("Onboarding transition unavailable:")
        })
        .unwrap_or_else(|error| panic!("{error}"));
    let screen = session.snapshot().contents();
    assert!(
        screen.contains("Choose your default model"),
        "Provider Done must settle into native Model without a transition error:\n{screen}"
    );
}

fn complete_model(session: &mut HermeticCockpit, input: WalkthroughInput) {
    for (label, next) in [
        ("[ Continue ]", "Provider trust"),
        ("[ Continue ]", "Model capabilities"),
        ("[ Continue ]", "Model limits"),
        ("[ Continue ]", "Default thinking"),
        ("[ Continue ]", "Delegation"),
    ] {
        activate(session, input, label);
        wait_for_text(session, "next model sub-step", next);
    }
    activate(session, input, "[ Continue ]");
    wait_for_text(session, "agent authoring screen", "Create your first agent");
}

fn confirm_first_unset_trust(session: &mut HermeticCockpit, input: WalkthroughInput) {
    let screen = session.snapshot().contents();
    let label = screen
        .lines()
        .find_map(|line| {
            let start = line.find("Confirm ")?;
            let rest = &line[start..];
            let end = rest.find(" as unset")? + " as unset".len();
            Some(rest[..end].to_string())
        })
        .unwrap_or_else(|| panic!("expected an unset trust row:\n{screen}"));
    match input {
        WalkthroughInput::Keyboard => {
            keyboard_input(session, b" ");
            keyboard_input(session, b"\r");
        }
        WalkthroughInput::Mouse => {
            click_text_twice(session, &label);
            click_text(session, "[ Continue ]");
        }
    }
}

fn complete_runner_editor(session: &mut HermeticCockpit, input: WalkthroughInput) {
    match input {
        WalkthroughInput::Keyboard => keyboard_input(session, b"e"),
        WalkthroughInput::Mouse => click_text(session, "▸ runner"),
    }
    wait_for_text(session, "runner identity", "Subagent");
    activate(session, input, "[ Continue ]");
    wait_for_text(session, "runner model grants", "Subagent models");
    activate(session, input, "[ Continue ]");
    session
        .wait_until_screen(
            "runner trust or optimizations",
            TRANSITION_TIMEOUT,
            |screen| {
                screen.contains("How much does this subagent see?")
                    || screen.contains("Tune the subagent")
                    || screen.contains("Subagent tools")
            },
        )
        .expect("runner advances beyond model grants");
    if session
        .snapshot()
        .contains("How much does this subagent see?")
    {
        confirm_first_unset_trust(session, input);
        session
            .wait_until_screen("runner optimizations", TRANSITION_TIMEOUT, |screen| {
                screen.contains("Tune the subagent") || screen.contains("Subagent tools")
            })
            .expect("runner trust advances");
    }
    if session.snapshot().contains("Tune the subagent") {
        activate(session, input, "[ Continue ]");
        wait_for_text(session, "runner tools", "Subagent tools");
    }
    activate(session, input, "[ Continue ]");
    session
        .wait_until_screen("runner editor saved", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Define subagents") || screen.contains("Subagent helpers")
        })
        .expect("runner tools advance");
    if session.snapshot().contains("Subagent helpers") {
        activate(session, input, "[ Save ]");
        wait_for_text(session, "runner saved", "Define subagents");
    }
}

fn complete_agent(session: &mut HermeticCockpit, input: WalkthroughInput) {
    activate(session, input, "[ Continue ]");
    wait_for_text(session, "agent model grants", "Choose the agent's models");
    activate(session, input, "[ Continue ]");
    session
        .wait_until_screen(
            "agent trust or optimizations",
            TRANSITION_TIMEOUT,
            |screen| {
                screen.contains("How much does this agent see?")
                    || screen.contains("Tune the agent")
            },
        )
        .expect("agent advances beyond model grants");
    if session.snapshot().contains("How much does this agent see?") {
        confirm_first_unset_trust(session, input);
        wait_for_text(session, "agent optimizations", "Tune the agent");
    }
    activate(session, input, "[ Continue ]");
    wait_for_text(session, "agent tools", "Grant tools");
    activate(session, input, "[ Continue ]");
    wait_for_text(session, "agent subagents", "Define subagents");
    complete_runner_editor(session, input);

    activate(session, input, "[ Continue ]");
    wait_for_text(session, "agent review", "Ready to create");
    activate(session, input, "[ Create agent ]");
    wait_for_text(session, "agent creation confirmation", "Create your agent");
    activate(session, input, "[ Create agent ]");
    wait_for_text(session, "lifetime screen", "Background agents");
}

fn assert_daemon_onboarding_complete(session: &HermeticCockpit) {
    let socket = session.socket_path();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build onboarding assertion runtime");
    runtime.block_on(async move {
        let client = cockpit_client::DaemonClient::connect(&socket)
            .await
            .expect("connect to spawned onboarding daemon");
        let response = client
            .request_ok(cockpit_proto::Request::GetOnboardingBootstrapSnapshot)
            .await
            .expect("read daemon onboarding snapshot");
        let cockpit_proto::Response::OnboardingBootstrapSnapshot(Some(snapshot)) = response else {
            panic!("expected an onboarding snapshot, got {response:?}");
        };
        assert_eq!(snapshot.stage, cockpit_proto::OnboardingStage::Complete);
    });
}

fn complete_cold_first_run(input: WalkthroughInput) {
    let (provider_url, provider_shutdown) = spawn_loopback_models_provider();
    let mut session = HermeticCockpit::prepare_fresh(HermeticProfile::Default);
    session.set_extra_env("COCKPIT_REDUCE_MOTION", "1");
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn complete cold first-run PTY child");

    wait_for_text(
        &mut session,
        "cold first-run Welcome shell",
        "[press any button to continue]",
    );
    activate(&mut session, input, "[press any button to continue]");
    wait_for_text(
        &mut session,
        "profile screen",
        "What should Cockpit call you?",
    );
    session.write_str("Ada");
    activate(&mut session, input, "[ Continue ]");
    wait_for_text(&mut session, "secure-store screen", "Secure your secrets");
    match input {
        WalkthroughInput::Keyboard => {
            if session.snapshot().contents().contains("◉ Platform keyring") {
                keyboard_input(&mut session, b"\x1b[B");
            }
            keyboard_input(&mut session, b"\x1b[B");
            keyboard_input(&mut session, b"\r");
        }
        WalkthroughInput::Mouse => click_text_twice(&mut session, "Machine-bound encrypted file"),
    }
    wait_for_text(&mut session, "provider catalog", "Let's add a provider");
    session.wait_for_daemon_handshake(TRANSITION_TIMEOUT);
    configure_custom_provider(&mut session, input, &provider_url);

    complete_model(&mut session, input);
    complete_agent(&mut session, input);
    activate(&mut session, input, "[ Continue ]");
    wait_for_text(&mut session, "completion summary", "You're ready to fly");
    assert_daemon_onboarding_complete(&session);
    activate(&mut session, input, "[ Start coding ]");
    wait_for_text(
        &mut session,
        "ready chat after onboarding",
        COMPOSER_PLACEHOLDER,
    );

    // A separate process against the same isolated installation must skip
    // onboarding and attach directly to the ready session.
    session.reap();
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn second PTY launch");
    wait_for_text(
        &mut session,
        "ready chat on second launch",
        COMPOSER_PLACEHOLDER,
    );
    assert_daemon_onboarding_complete(&session);

    provider_shutdown.store(true, Ordering::Relaxed);
    session.reap();
    session.stop_child_spawned_daemon();
    session.assert_reaped();
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

#[test]
fn tui_pty_cold_first_run_keyboard_completes_and_second_launch_is_ready() {
    complete_cold_first_run(WalkthroughInput::Keyboard);
}

#[test]
fn tui_pty_cold_first_run_mouse_completes_and_second_launch_is_ready() {
    complete_cold_first_run(WalkthroughInput::Mouse);
}
