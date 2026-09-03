//! Executable release acceptance for a fresh, offline, no-account install.

use std::io::Read as _;
use std::process::{Command, Output};
use std::{net::TcpListener, time::Duration};

use crate::support::{HermeticCockpit, HermeticProfile, output_text};
use cockpit_test_support::provider::{ScriptedProvider, Turn};

const PUBLIC_SNAPSHOT: &str = include_str!("../fixtures/public-v0.1-command-snapshot.json");

fn public_commands() -> Vec<String> {
    let snapshot: serde_json::Value = serde_json::from_str(PUBLIC_SNAPSHOT).unwrap();
    // The snapshot pins the full public surface (roots plus aliases); help
    // output lists canonical roots only, so narrow to those here.
    let canonical: std::collections::BTreeSet<String> =
        cockpit_cli::public_v0_1_command()
            .get_subcommands()
            .map(|subcommand| subcommand.get_name().to_owned())
            .collect();
    snapshot["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .filter(|command| canonical.contains(command))
        .collect()
}

fn help_lists_root(help: &str, root: &str) -> bool {
    help.lines()
        .any(|line| line.split_whitespace().next() == Some(root))
}

fn completion_lists_root(completion: &str, root: &str) -> bool {
    completion
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '-'))
        .any(|token| token == root)
}

fn run(session: &HermeticCockpit, args: &[&str]) -> Output {
    run_with_env(session, args, std::iter::empty::<(String, String)>())
}

fn run_with_env(
    session: &HermeticCockpit,
    args: &[&str],
    extra_env: impl IntoIterator<Item = (String, String)>,
) -> Output {
    let mut command = Command::new(session.spec().executable());
    command
        .env_clear()
        .envs(session.spec().subprocess_env())
        .envs(extra_env)
        .current_dir(session.project_path())
        .args(args)
        .output()
        .unwrap()
}

fn deny_proxy() -> (TcpListener, Vec<(String, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let mut env = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]
        .into_iter()
        .map(|name| (name.to_string(), proxy.clone()))
        .collect::<Vec<_>>();
    env.push(("NO_PROXY".into(), "127.0.0.1,localhost".into()));
    (listener, env)
}

fn install_network_deny_recorder(session: &mut HermeticCockpit) -> TcpListener {
    let (listener, policy) = deny_proxy();
    for (key, value) in policy {
        session.set_extra_env(key, value);
    }
    listener
}

fn assert_no_network_attempt(listener: &TcpListener) {
    std::thread::sleep(Duration::from_millis(25));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "local acceptance attempted a non-allowlisted outbound HTTP(S) connection"
    );
}

#[test]
fn public_help_and_completion_expose_exact_v0_1_roots() {
    let session = HermeticCockpit::prepare(HermeticProfile::Default);
    let help = run(&session, &["--help"]);
    assert!(help.status.success(), "{}", output_text(&help));
    let text = output_text(&help);
    let public = public_commands();
    for command in &public {
        assert!(help_lists_root(&text, command), "missing {command}: {text}");
    }
    // The local profile compiles only local commands: every root implemented
    // in this build is public, so the only absent roots are the feature-gated
    // remote/extended commands.
    for hidden in ["account", "sync", "connect", "schedule"] {
        assert!(!help_lists_root(&text, hidden), "leaked {hidden}: {text}");
    }
    for allowed in &public {
        let output = run(&session, &[allowed.as_str(), "--help"]);
        assert!(
            output.status.success(),
            "allowed root {allowed} did not parse: {}",
            output_text(&output)
        );
    }
    for rejected in ["providers", "auth", "schedule"] {
        let output = run(&session, &[rejected, "--help"]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "non-public root {rejected} parsed: {}",
            output_text(&output)
        );
    }
    // `completion` is public: generating a script from the release binary
    // succeeds and mirrors the release-asset generator.
    let generated = run(&session, &["completion", "bash"]);
    assert!(generated.status.success(), "{}", output_text(&generated));
    let mut completion = Vec::new();
    clap_complete::generate(
        clap_complete::Shell::Bash,
        &mut cockpit_cli::public_v0_1_command(),
        "cockpit",
        &mut completion,
    );
    let completion = String::from_utf8(completion).unwrap();
    for command in &public {
        assert!(
            completion_lists_root(&completion, command),
            "completion omitted {command}"
        );
    }
    for hidden in ["account", "sync", "connect", "schedule"] {
        assert!(
            !completion_lists_root(&completion, hidden),
            "completion leaked {hidden}"
        );
    }
}

#[test]
fn fresh_state_missing_provider_and_daemon_tui_are_offline_stable() {
    let mut session = HermeticCockpit::prepare(HermeticProfile::Default);
    session.enable_isolated_secret_service();
    let denied_network = install_network_deny_recorder(&mut session);
    std::fs::remove_file(session.home().config_dir().join("providers/local.json")).unwrap();
    let doctor = run(&session, &["doctor", "--offline"]);
    assert_eq!(doctor.status.code(), Some(1), "{}", output_text(&doctor));
    assert!(
        output_text(&doctor).contains("no providers configured"),
        "{}",
        output_text(&doctor)
    );
    assert_no_network_attempt(&denied_network);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn isolated_settings_export_and_restart_resume_paths_execute_without_accounts() {
    let provider = ScriptedProvider::builder()
        .turn(Turn::Text("durable release reply".into()))
        .repeat_last()
        .start()
        .await;
    let mut session = HermeticCockpit::prepare(HermeticProfile::Default);
    session
        .home()
        .write_local_provider_config(&provider.base_url());
    std::fs::write(
        session.project_path().join(".env"),
        "RELEASE_ACCEPTANCE_TOKEN=release-acceptance-secret-7f31\n",
    )
    .unwrap();
    session.enable_isolated_secret_service();
    let denied_network = install_network_deny_recorder(&mut session);
    // This is the suite's only sandboxed `doctor --offline` invocation.
    // Keep it sandboxed so hermetic PATH + containment stay covered.
    let clean_doctor = run(&session, &["doctor", "--offline"]);
    assert!(
        clean_doctor.status.success(),
        "{}",
        output_text(&clean_doctor)
    );
    session.start_trusted_daemon();
    session.spawn_pty(100, 30).unwrap();
    session.wait_until_ready(Duration::from_secs(30)).unwrap();
    assert!(session.snapshot().contents().contains("Message"));

    let secret = "release-acceptance-secret-7f31";
    let prompt = format!("durable release prompt {secret}");
    let turn = run(&session, &["run", "--json", &prompt]);
    assert!(turn.status.success(), "{}", output_text(&turn));
    let events = String::from_utf8_lossy(&turn.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .collect::<Vec<_>>();
    let session_id = events
        .iter()
        .find(|event| event["event"] == "session_attached")
        .and_then(|event| event["session_id"].as_str())
        .expect("successful turn session id")
        .to_owned();
    assert!(
        events
            .iter()
            .any(|event| event.to_string().contains("durable release reply"))
    );

    let policy = session.project_path().join("portable-policy.json");
    let export = session.project_path().join("session-export.zip");
    let policy_text = policy.to_string_lossy().into_owned();
    let export_text = export.to_string_lossy().into_owned();
    for args in [
        vec!["config", "export-policy", "--output", &policy_text],
        vec!["config", "import-policy", &policy_text, "--replace"],
        vec!["daemon", "restart"],
        vec!["daemon", "status"],
        vec!["export", &session_id, "--output", &export_text],
    ] {
        let output = run(&session, &args);
        assert!(
            output.status.success(),
            "{}: {}",
            args.join(" "),
            output_text(&output)
        );
    }
    assert!(policy.is_file(), "settings policy was not persisted");
    assert!(export.is_file(), "redacted session export was not created");
    // `cockpit import` round-trips `cockpit export`: the archive is pushed as
    // bounded bulk chunks, verified by the daemon, and restored with fresh
    // destination session ids (never restoring approval grants).
    let imported = run(&session, &["import", &export_text]);
    assert!(
        imported.status.success(),
        "import failed: {}",
        output_text(&imported)
    );
    assert!(
        output_text(&imported).contains("Imported 1 session"),
        "import did not round-trip the export archive: {}",
        output_text(&imported)
    );
    let resumed = run(
        &session,
        &[
            "run",
            "--session",
            &session_id,
            "--json",
            "resume exact session",
        ],
    );
    assert!(resumed.status.success(), "{}", output_text(&resumed));
    assert!(
        provider.captured().iter().any(|request| {
            let body = request.body.to_string();
            body.contains("durable release prompt")
                && body.contains("durable release reply")
                && body.contains("resume exact session")
        }),
        "resumed provider request did not contain the durable prior content"
    );
    let file = std::fs::File::open(export).unwrap();
    let mut archive = zip::ZipArchive::new(file).unwrap();
    let mut exported = String::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).unwrap();
        if entry.is_file() {
            let _ = entry.read_to_string(&mut exported);
        }
    }
    assert!(exported.contains("durable release reply"));
    assert!(
        !exported.contains(secret),
        "redacted export leaked env-derived secret"
    );
    assert_no_network_attempt(&denied_network);
    assert!(
        !provider.captured().is_empty(),
        "scripted provider saw no successful turn"
    );
}
