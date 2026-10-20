//! Cold first-run onboarding over a real PTY (#425).
//!
//! Unlike the configured-installation fixtures, this scenario starts from
//! `IsolatedHome::new_fresh()`: no database, no onboarding authority, no
//! provider config, and no pre-started daemon. The PTY child's TUI must
//! spawn the daemon itself, present the Welcome shell, and advance to the
//! Profile stage with a single keystroke — the exact path that used to
//! wedge silently at step 1.

use std::io::{self, Read, Write};
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

/// Own the listener thread on success and panic paths. In particular, a
/// detached mock panic must not masquerade as a missing-secret product error.
struct LoopbackModelsProvider {
    url: String,
    shutdown: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Drop for LoopbackModelsProvider {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                result.expect("loopback provider thread");
            }
        }
    }
}

fn has_fixture_authorization(headers: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value.trim() == "Bearer test-key"
        })
    })
}

/// No bytes followed by EOF/idle timeout is an unused connection. Once a
/// request starts, truncated headers/bodies and read errors remain failures.
fn read_provider_request(socket: &mut impl Read) -> io::Result<Option<String>> {
    const HEADER_LIMIT: usize = 64 * 1024;
    let mut received = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let end = end + 4;
            if end <= HEADER_LIMIT {
                break end;
            }
        }
        if received.len() >= HEADER_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bounded provider request headers",
            ));
        }
        match socket.read(&mut chunk) {
            Ok(0) if received.is_empty() => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete provider request headers",
                ));
            }
            Ok(read) => received.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if received.is_empty()
                    && matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        }
    };
    let headers = std::str::from_utf8(&received[..header_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .to_owned();
    let length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>())
        })
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .unwrap_or(0);
    if length >= 4 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded provider request body",
        ));
    }
    let remaining = (header_end + length).saturating_sub(received.len());
    socket.take(remaining as u64).read_to_end(&mut received)?;
    if received.len() < header_end + length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "incomplete provider request body",
        ));
    }
    Ok(Some(headers))
}

fn spawn_loopback_models_provider() -> LoopbackModelsProvider {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake provider");
    listener
        .set_nonblocking(true)
        .expect("make fake provider nonblocking");
    let provider_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = Arc::clone(&shutdown);
    let worker = std::thread::spawn(move || {
        let body = r#"{"data":[{"id":"scripted","object":"model","context_length":131072,"max_output_tokens":8192,"supported_parameters":["tools"]},{"id":"fallback","object":"model","context_length":131072,"max_output_tokens":8192,"supported_parameters":["tools"]}],"object":"list"}"#;
        while !shutdown_flag.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("provider read timeout");
                    socket
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .expect("provider write timeout");
                    let request = match read_provider_request(&mut socket) {
                        Ok(Some(request)) => request,
                        // A preflight or cancelled connection never establishes
                        // credential proof. Reject it and keep serving clients.
                        Ok(None) => continue,
                        Err(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::UnexpectedEof
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::BrokenPipe
                                    | io::ErrorKind::WouldBlock
                                    | io::ErrorKind::TimedOut
                            ) =>
                        {
                            eprintln!("abandoned provider request: {error}");
                            continue;
                        }
                        Err(error) => panic!("invalid provider request: {error}"),
                    };
                    let (content_type, response) = if request.starts_with("GET ") {
                        assert!(
                            has_fixture_authorization(&request),
                            "provider verification must authenticate with the onboarded key"
                        );
                        ("application/json", body.to_owned())
                    } else {
                        assert!(
                            has_fixture_authorization(&request),
                            "first inference must authenticate with the onboarded key"
                        );
                        ("text/event-stream", concat!(
                            "data: {\"id\":\"ux4\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"scripted\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"UX4_FIRST_SEND_OK\"},\"finish_reason\":null}]}\n\n",
                            "data: {\"id\":\"ux4\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"scripted\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n",
                            "data: [DONE]\n\n",
                        ).to_owned())
                    };
                    let _ = write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        response.len(),
                        response
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept provider connection: {error}"),
            }
        }
    });
    LoopbackModelsProvider {
        url: provider_url,
        shutdown,
        worker: Some(worker),
    }
}

#[test]
fn ux4_loopback_provider_survives_unused_connections_and_serves_authenticated_requests() {
    let provider = spawn_loopback_models_provider();
    let address = provider
        .url
        .strip_prefix("http://")
        .unwrap()
        .strip_suffix("/v1")
        .unwrap();
    drop(std::net::TcpStream::connect(address).unwrap());
    let mut abandoned = std::net::TcpStream::connect(address).unwrap();
    abandoned.write_all(b"GET /v1/models HTTP/1.1\r\n").unwrap();
    abandoned.shutdown(std::net::Shutdown::Write).unwrap();
    let mut rejected = Vec::new();
    abandoned
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    abandoned.read_to_end(&mut rejected).unwrap();
    assert!(
        rejected.is_empty(),
        "incomplete requests cannot verify a key"
    );
    for (request, expected) in [
        (
            "GET /v1/models HTTP/1.1\r\nAuthorization: Bearer test-key\r\n\r\n",
            "\"object\":\"list\"",
        ),
        (
            "POST /v1/chat/completions HTTP/1.1\r\nAuthorization: Bearer test-key\r\nContent-Length: 2\r\n\r\n{}",
            "UX4_FIRST_SEND_OK",
        ),
    ] {
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        // Exercise headers and body delivered over multiple writes.
        for chunk in request.as_bytes().chunks(7) {
            socket.write_all(chunk).unwrap();
        }
        let mut response = String::new();
        socket.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains(expected), "{response}");
    }
}

#[test]
fn ux4_loopback_provider_rejects_incomplete_and_oversized_requests() {
    for request in [
        b"GET /v1/models HTTP/1.1\r\n".to_vec(),
        b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 2\r\n\r\n{".to_vec(),
    ] {
        let error = read_provider_request(&mut request.as_slice()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }
    for request in [
        vec![b'x'; 64 * 1024],
        b"POST / HTTP/1.1\r\nContent-Length: 4194304\r\n\r\n".to_vec(),
        b"POST / HTTP/1.1\r\nContent-Length: invalid\r\n\r\n".to_vec(),
    ] {
        let error = read_provider_request(&mut request.as_slice()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn ux4_loopback_provider_distinguishes_idle_from_partial_request_timeout() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert!(read_provider_request(&mut server).unwrap().is_none());
    client.write_all(b"GET /v1/models HTTP/1.1\r\n").unwrap();
    let error = read_provider_request(&mut server).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
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

/// The locked daemon serves onboarding before its host probes settle, so the
/// secure-store screen first renders every placement as `checking…` and
/// accepts no choice. Wait for the settled capability rows before choosing a
/// placement; input sent while probing is intentionally ignored.
fn wait_for_settled_secure_store(session: &mut HermeticCockpit) {
    session
        .wait_until_screen(
            "settled secure-store capability rows",
            ASYNC_STAGE_TIMEOUT,
            |screen| {
                screen.contains("step 2/5")
                    && screen.contains("Secure your secrets")
                    && screen.contains("Machine-bound encrypted file  —  ")
                    && !screen.contains("checking…")
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
}

fn wait_for_text(session: &mut HermeticCockpit, label: &str, needle: &str) {
    session
        .wait_until_screen(label, ASYNC_STAGE_TIMEOUT, |screen| screen.contains(needle))
        .unwrap_or_else(|error| panic!("{error}"));
}

fn daemon_generation(session: &HermeticCockpit) -> u64 {
    let rendezvous = session.home().rendezvous_files().rendezvous;
    let bytes = std::fs::read(&rendezvous)
        .unwrap_or_else(|error| panic!("read daemon rendezvous {rendezvous:?}: {error}"));
    serde_json::from_slice::<serde_json::Value>(&bytes)
        .expect("decode daemon rendezvous")
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .expect("daemon rendezvous has a numeric generation")
}

fn assert_daemon_stays_alive(session: &HermeticCockpit, expected_generation: u64) {
    let deadline = Instant::now() + DAEMON_STABILITY_WINDOW;
    loop {
        assert_eq!(
            daemon_generation(session),
            expected_generation,
            "onboarding must retain its daemon across provider verification"
        );
        session.wait_for_daemon_handshake(TRANSITION_TIMEOUT);
        if Instant::now() >= deadline {
            return;
        }
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
    assert_daemon_stays_alive(session, generation);
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
    let screen = session.snapshot().contents();
    assert!(
        screen.contains("Search models"),
        "required picker must expose focused search: {screen}"
    );
    keyboard_input(session, b"scripted");
    activate(session, input, "[ Continue ]");
    session
        .wait_until_screen(
            "short model selection reaches workspace trust",
            ASYNC_STAGE_TIMEOUT,
            |screen| {
                screen.contains("Choose workspace trust:")
                    || screen.contains("Provider trust")
                    || screen.contains("Model capabilities")
                    || screen.contains("Create an agent")
                    || screen.contains("Grant tools")
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
    let screen = session.snapshot().contents();
    assert!(
        screen.contains("Choose workspace trust:"),
        "default model must bypass optional model/agent pages: {screen}"
    );
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
        WalkthroughInput::Keyboard => {
            keyboard_input(session, b"\x1b[H");
            keyboard_input(session, b"e");
        }
        WalkthroughInput::Mouse => click_text(session, "runner  ·"),
    }
    session
        .wait_until_screen("runner identity", TRANSITION_TIMEOUT, |screen| {
            screen.contains("Subagent · step") && screen.contains("runner")
        })
        .expect("the runner row must open its identity editor");
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
    keyboard_input(session, b"Optional Pilot");
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
    wait_for_text(session, "optional agent committed", "Your agent is ready");
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

fn saved_code_sessions(session: &HermeticCockpit) -> usize {
    let socket = session.socket_path();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let client = cockpit_client::DaemonClient::connect(&socket)
                .await
                .unwrap();
            let response = client
                .request_ok(cockpit_proto::Request::ListSessions {
                    project_id: None,
                    parent_session_id: None,
                    assistant_id: None,
                    compaction_lineage_root_id: None,
                    include_archived: false,
                })
                .await
                .unwrap();
            let cockpit_proto::Response::Sessions { sessions } = response else {
                panic!("expected session list");
            };
            sessions
                .into_iter()
                .filter(|session| session.session_entry_mode == "code")
                .count()
        })
}

fn complete_cold_first_run(input: WalkthroughInput) {
    let provider = spawn_loopback_models_provider();
    // Force the connection lifecycle that used to kill the detached mock.
    // It must still serve the subsequent authenticated onboarding and send.
    drop(
        std::net::TcpStream::connect(
            provider
                .url
                .strip_prefix("http://")
                .unwrap()
                .strip_suffix("/v1")
                .unwrap(),
        )
        .expect("unused provider connection"),
    );
    let mut session = HermeticCockpit::prepare_fresh(HermeticProfile::Default);
    session.set_extra_env("COCKPIT_REDUCE_MOTION", "1");
    session.set_extra_env("COCKPIT_LOG", "warn,cockpit_core::daemon=info");
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
    wait_for_settled_secure_store(&mut session);
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
    configure_custom_provider(&mut session, input, &provider.url);

    complete_model(&mut session, input);
    // Complete unlocks the real workspace decision; it is deliberately not
    // seeded by the fixture. Both input routes answer the visible modal.
    wait_for_text(
        &mut session,
        "workspace trust decision",
        "Choose workspace trust:",
    );
    activate(&mut session, input, "1. trust - open");
    wait_for_text(&mut session, "completion summary", "You're ready to fly");
    assert_daemon_onboarding_complete(&session);
    activate(&mut session, input, "[ Start coding ]");
    wait_for_text(
        &mut session,
        "ready chat after onboarding",
        COMPOSER_PLACEHOLDER,
    );

    // The required path ends in a usable first conversation, not merely a
    // Connected model catalog. Check persistence via the real daemon RPC.
    assert_eq!(saved_code_sessions(&session), 0);
    let provider_path = session.home().config_dir().join("providers/localtest.json");
    let provider: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&provider_path).unwrap()).unwrap();
    assert!(
        !serde_json::to_string(&provider)
            .unwrap()
            .contains("test-key"),
        "onboarding must persist a named reference, never the key literal"
    );
    let reference = provider["headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|header| {
            header["name"]
                .as_str()
                .is_some_and(|name| name.eq_ignore_ascii_case("Authorization"))
        })
        .unwrap()["value"]
        .as_str()
        .unwrap()
        .strip_prefix("$secret:")
        .unwrap()
        .to_owned();
    // Fault only this throwaway encrypted item. Preserve provider bytes and
    // installed binding provenance; no plaintext or real-user store is read.
    let vault_fixture = rusqlite::Connection::open(session.home().db_path()).unwrap();
    vault_fixture.execute("CREATE TEMP TABLE ux4_saved_named_secret AS SELECT * FROM secret_vault_items WHERE kind = 'named_secret' AND item_id = ?1", [&reference]).unwrap();
    assert_eq!(
        vault_fixture
            .execute(
                "DELETE FROM secret_vault_items WHERE kind = 'named_secret' AND item_id = ?1",
                [&reference]
            )
            .unwrap(),
        1
    );
    keyboard_input(&mut session, b"Reply briefly without tools.");
    for _ in 0..2 {
        let failures_before = session
            .snapshot()
            .contents()
            .matches("Could not create session")
            .count();
        keyboard_input(&mut session, b"\r");
        session
            .wait_until_screen(
                "failed attach retains draft",
                ASYNC_STAGE_TIMEOUT,
                |screen| {
                    let text = screen.contents();
                    // The long opaque name wraps in a real terminal. Preserve
                    // the exact ID assertion while ignoring layout whitespace.
                    let latest_names =
                        text.rsplit_once("Could not create session")
                            .map(|(_, latest)| {
                                latest
                                    .chars()
                                    .filter(|ch| !ch.is_whitespace())
                                    .collect::<String>()
                            });
                    latest_names.is_some_and(|latest| latest.contains(&reference))
                        && text.matches("Could not create session").count() > failures_before
                },
            )
            .unwrap();
        let screen = session.snapshot().contents();
        assert!(screen.contains("Draft (unsaved)"), "{screen}");
        assert!(screen.contains("Reply briefly without tools."), "{screen}");
        assert_eq!(
            saved_code_sessions(&session),
            0,
            "failed first send and retry must not save rows"
        );
        assert_eq!(
            vault_fixture
                .query_row(
                    "SELECT count(*) FROM sessions WHERE session_entry_mode = 'code'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0,
            "failed preparation must be removed, including its internal parent"
        );
    }
    assert_eq!(
        vault_fixture
            .execute(
                "INSERT INTO secret_vault_items SELECT * FROM temp.ux4_saved_named_secret",
                []
            )
            .unwrap(),
        1
    );
    keyboard_input(&mut session, b"\r");
    wait_for_text(
        &mut session,
        "authenticated first inference",
        "UX4_FIRST_SEND_OK",
    );
    assert_eq!(saved_code_sessions(&session), 1);
    assert!(
        !session.snapshot().contents().contains("Draft (unsaved)"),
        "successful first send must leave draft mode"
    );
    keyboard_input(&mut session, b"/new");
    keyboard_input(&mut session, b"\r");
    wait_for_text(&mut session, "unsaved second composer", "Draft (unsaved)");
    assert_eq!(saved_code_sessions(&session), 1);

    // Advanced agent controls remain usable as an optional /setup route.
    // Keep the complete keyboard/mouse model grants, tuning, tool grants,
    // runner editing, review, and Create coverage off the required path.
    session.settle_visible_state(TRANSITION_TIMEOUT);
    keyboard_input(&mut session, b"/setup");
    keyboard_input(&mut session, b"\r");
    wait_for_text(
        &mut session,
        "optional setup summary",
        "You're ready to fly",
    );
    match input {
        WalkthroughInput::Keyboard => keyboard_input(&mut session, b"g"),
        WalkthroughInput::Mouse => click_text(&mut session, "[ Agent setup ]"),
    }
    wait_for_text(&mut session, "optional agent setup", "Create an agent");
    complete_agent(&mut session, input);
    assert_daemon_onboarding_complete(&session);
    activate(&mut session, input, "[ Done ]");
    wait_for_text(
        &mut session,
        "ready after optional agent authoring",
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
            |screen| screen.contains("step 1/5"),
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
                screen.contains("step 1/5") && screen.contains("What should Cockpit call you?")
            },
        )
        .expect("Welcome pointer advance reaches Profile");

    session.write_str("Ada");
    click_text(&mut session, "[ Continue ]");
    session
        .wait_until_screen(
            "Secure store after profile save",
            TRANSITION_TIMEOUT,
            |screen| screen.contains("step 2/5") && screen.contains("Secure your secrets"),
        )
        .expect("Profile Continue reaches Secure store");
    wait_for_settled_secure_store(&mut session);

    click_text_twice(&mut session, "Machine-bound encrypted file");
    session
        .wait_until_screen(
            "Provider catalog after secure-store choice",
            TRANSITION_TIMEOUT,
            |screen| {
                screen.contains("step 3/5")
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

/// Onboarding-screen markers that must never appear on an onboarded home.
const ONBOARDING_MARKERS: [&str; 4] = [
    "[press any button to continue]",
    "What should Cockpit call you?",
    "Secure your secrets",
    "step 1/5",
];

/// Flicker-free startup: the TUI asks the daemon whether onboarding is needed
/// before it enters the alternate screen, so the very first frame on a fresh
/// home — and every frame after it — is the onboarding shell, never a chat UI
/// that onboarding replaces a moment later.
#[test]
fn tui_pty_first_frame_is_onboarding_on_a_fresh_home() {
    let mut session = HermeticCockpit::prepare_fresh(HermeticProfile::Default);
    session.set_extra_env("COCKPIT_REDUCE_MOTION", "1");
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn cold first-run PTY child");
    session
        .wait_until_screen(
            "cold first-run Welcome shell",
            COLD_WELCOME_TIMEOUT,
            |screen| screen.contains("[press any button to continue]"),
        )
        .expect("cold first-run reaches the Welcome shell");
    let frames = session.synchronized_frame_snapshots();
    assert!(!frames.is_empty(), "the TUI drew no synchronized frame");
    assert!(
        frames[0].contains("[press any button to continue]"),
        "the first frame on a fresh home must already be the onboarding Welcome:\n{}",
        frames[0].contents()
    );
    for (index, frame) in frames.iter().enumerate() {
        assert!(
            !frame.contains(COMPOSER_PLACEHOLDER) && !frame.contains("Starting cockpit"),
            "frame {index} before the Welcome settled showed chat or the pre-screen notice:\n{}",
            frame.contents()
        );
    }
    eprintln!(
        "first-frame-timing fresh-home launch_to_first_frame_ms={}",
        session
            .launch_to_first_frame()
            .expect("first frame timestamp")
            .as_millis()
    );

    session.reap();
    session.stop_child_spawned_daemon();
    session.assert_reaped();
}

fn assert_every_frame_is_chat_until_ready(session: &mut HermeticCockpit, label: &str) {
    session
        .wait_until_screen(label, COLD_WELCOME_TIMEOUT, |screen| {
            screen.contains(COMPOSER_PLACEHOLDER)
        })
        .expect("an onboarded home opens the chat UI");
    let frames = session.synchronized_frame_snapshots();
    assert!(!frames.is_empty(), "the TUI drew no synchronized frame");
    assert!(
        frames[0].contains(COMPOSER_PLACEHOLDER),
        "the first frame on an onboarded home must be the chat UI:\n{}",
        frames[0].contents()
    );
    for (index, frame) in frames.iter().enumerate() {
        for marker in ONBOARDING_MARKERS {
            assert!(
                !frame.contains(marker),
                "frame {index} on an onboarded home drew onboarding (`{marker}`):\n{}",
                frame.contents()
            );
        }
    }
}

/// Flicker-free startup, onboarded home with a running daemon: every frame is
/// the chat UI and no onboarding surface is ever drawn.
#[test]
fn tui_pty_first_frame_is_chat_on_an_onboarded_home() {
    let mut session = HermeticCockpit::prepare(HermeticProfile::Default);
    session.start_trusted_daemon();
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn onboarded PTY child");
    assert_every_frame_is_chat_until_ready(&mut session, "ready chat (warm daemon)");
    eprintln!(
        "first-frame-timing warm-onboarded launch_to_first_frame_ms={}",
        session
            .launch_to_first_frame()
            .expect("first frame timestamp")
            .as_millis()
    );
    session.reap();
    session.assert_reaped();
}

/// Cold onboarded start: no daemon is running, so the TUI spawns it. The
/// first frame is still the chat UI (decided from the daemon's early
/// bootstrap answer), never onboarding, and it does not wait for the full
/// ready-service boot.
#[test]
fn tui_pty_first_frame_is_chat_on_a_cold_onboarded_home() {
    let mut session = HermeticCockpit::prepare(HermeticProfile::Default);
    // Record the workspace-trust decision, then stop that daemon: the PTY
    // launch below starts from a cold (daemon-less) onboarded home.
    session.start_trusted_daemon();
    session.stop_child_spawned_daemon();
    session.forget_fixture_daemon_ownership();
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn cold onboarded PTY child");
    assert_every_frame_is_chat_until_ready(&mut session, "ready chat (cold daemon)");
    eprintln!(
        "first-frame-timing cold-onboarded launch_to_first_frame_ms={}",
        session
            .launch_to_first_frame()
            .expect("first frame timestamp")
            .as_millis()
    );
    // The first frame was painted from the locked bootstrap answer; observe
    // the handoff to ready services behind it: the daemon reports ready, the
    // in-chat "starting services" status clears, and no frame across the
    // whole window drew onboarding or a startup failure.
    let deadline = Instant::now() + COLD_WELCOME_TIMEOUT;
    loop {
        let status = session.daemon_status_json();
        if status["state"] == "ready" {
            break;
        }
        assert_ne!(
            status["state"], "ready_construction_failed",
            "ready construction failed behind the first frame: {status}"
        );
        assert!(
            Instant::now() < deadline,
            "the daemon never became ready: {status}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    session
        .wait_until_screen("services ready", ASYNC_STAGE_TIMEOUT, |screen| {
            screen.contains(COMPOSER_PLACEHOLDER) && !screen.contains("Starting Cockpit services")
        })
        .expect("the starting-services status clears once ready services publish");
    for (index, frame) in session.synchronized_frame_snapshots().iter().enumerate() {
        for marker in ONBOARDING_MARKERS
            .iter()
            .chain(["could not start", "Daemon lifecycle unavailable"].iter())
        {
            assert!(
                !frame.contains(marker),
                "frame {index} across the ready handoff drew `{marker}`:\n{}",
                frame.contents()
            );
        }
    }
    session.reap();
    session.stop_child_spawned_daemon();
    session.assert_reaped();
}

/// D7/F9: a startup that fails before the first frame reports its error on
/// the normal terminal and leaves the terminal in cooked mode (echo and line
/// input restored), exactly as it found it. The failure is forced by an
/// endpoint that answers with a malformed hello (a terminal connect failure).
#[cfg(unix)]
#[test]
fn tui_pty_pre_paint_failure_restores_the_terminal() {
    let mut session = HermeticCockpit::prepare(HermeticProfile::Default);
    let socket = session.socket_path();
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent).expect("socket directory");
    }
    let _ = std::fs::remove_file(&socket);
    let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind impostor");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let _ = stream.write_all(b"this is not a cockpit hello\n");
        }
    });
    session
        .spawn_pty(INITIAL_PTY_COLS, INITIAL_PTY_ROWS)
        .expect("spawn PTY child");
    session
        .wait_until_screen("startup failure", COLD_WELCOME_TIMEOUT, |screen| {
            screen.contains("could not start")
        })
        .expect("the failure is reported on the normal terminal");
    let succeeded = session.wait_for_child_exit_status();
    assert_eq!(succeeded, Some(false), "a failed startup exits nonzero");
    assert!(
        session.synchronized_frame_snapshots().is_empty(),
        "no frame is drawn for a startup that failed before deciding a screen"
    );
    assert_eq!(
        session.pty_is_cooked(),
        Some(true),
        "the pre-paint raw mode is restored on failure"
    );
    session.reap();
    let _ = std::fs::remove_file(&socket);
}
