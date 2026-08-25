//! Executable release acceptance for a fresh, offline, no-account install.

use std::io::Read as _;
use std::process::{Command, Output};
use std::{net::TcpListener, time::Duration};

use crate::support::{HermeticCockpit, HermeticProfile, output_text};
use cockpit_test_support::provider::{ScriptedProvider, Turn};

const PUBLIC: &[&str] = &[
    "ask", "run", "agent", "provider", "setup", "models", "daemon", "doctor", "session", "trust",
    "export", "config", "init",
];

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

fn poison_flycockpit_endpoints(session: &HermeticCockpit) -> (TcpListener, Vec<(String, String)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let env = [
        "FLYCOCKPIT_API_URL",
        "FLYCOCKPIT_RELAY_URL",
        "FLYCOCKPIT_TENANT_AUTHORITY_URL",
    ]
    .into_iter()
    .map(|name| (name.to_string(), endpoint.clone()))
    .collect();
    (listener, env)
}

fn install_poison_endpoints(session: &mut HermeticCockpit) -> TcpListener {
    let (listener, endpoints) = poison_flycockpit_endpoints(session);
    for (key, value) in endpoints {
        session.set_extra_env(key, value);
    }
    listener
}

fn assert_no_network_attempt(listener: &TcpListener) {
    std::thread::sleep(Duration::from_millis(25));
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "local acceptance contacted a poisoned FlyCockpit endpoint"
    );
}

#[test]
fn public_help_and_completion_expose_exact_v0_1_roots() {
    let session = HermeticCockpit::prepare(HermeticProfile::Default);
    let help = run(&session, &["--help"]);
    assert!(help.status.success(), "{}", output_text(&help));
    let text = output_text(&help);
    for command in PUBLIC {
        assert!(
            text.lines()
                .any(|line| line.trim_start().starts_with(command)),
            "missing {command}: {text}"
        );
    }
    for hidden in [
        "account",
        "sync",
        "connect",
        "assistant",
        "invocation",
        "mcp",
        "schedule",
        "skill",
        "stats",
        "completion",
    ] {
        assert!(
            !text
                .lines()
                .any(|line| line.trim_start().starts_with(hidden)),
            "leaked {hidden}: {text}"
        );
    }
    for allowed in PUBLIC {
        let output = run(&session, &[allowed, "--help"]);
        assert!(
            output.status.success(),
            "allowed root {allowed} did not parse: {}",
            output_text(&output)
        );
    }
    for rejected in [
        "providers",
        "auth",
        "assistant",
        "invocation",
        "mcp",
        "schedule",
        "skill",
        "stats",
        "completion",
        "jq",
    ] {
        let output = run(&session, &[rejected, "--help"]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "non-public root {rejected} parsed: {}",
            output_text(&output)
        );
    }
    let rejected = run(&session, &["completion", "bash"]);
    assert_eq!(rejected.status.code(), Some(2));
    let mut completion = Vec::new();
    clap_complete::generate(
        clap_complete::Shell::Bash,
        &mut cockpit_cli::public_v0_1_command(),
        "cockpit",
        &mut completion,
    );
    let completion = String::from_utf8(completion).unwrap();
    for command in PUBLIC {
        assert!(completion.contains(command), "completion omitted {command}");
    }
    for hidden in ["account", "sync", "connect", "assistant", "mcp", "schedule"] {
        assert!(
            !completion.contains(&format!(" {hidden}")),
            "completion leaked {hidden}"
        );
    }
}

#[test]
fn fresh_state_missing_provider_and_daemon_tui_are_offline_stable() {
    let mut session = HermeticCockpit::prepare(HermeticProfile::Default);
    session.enable_isolated_secret_service();
    let poison = install_poison_endpoints(&mut session);
    std::fs::remove_file(session.home().config_dir().join("providers/local.json")).unwrap();
    let doctor = run(&session, &["doctor", "--offline"]);
    assert!(doctor.status.success(), "{}", output_text(&doctor));
    let models = run(&session, &["models"]);
    assert!(
        models.status.success() || models.status.code() == Some(4),
        "{}",
        output_text(&models)
    );
    let missing = output_text(&models).to_ascii_lowercase();
    assert!(
        missing.contains("provider")
            && (missing.contains("missing")
                || missing.contains("unavailable")
                || missing.contains("configured")),
        "missing-provider diagnostic was not explicit: {missing}"
    );
    session.start_trusted_daemon();
    session.spawn_pty(100, 30).unwrap();
    session
        .wait_until_ready(std::time::Duration::from_secs(30))
        .unwrap();
    assert!(session.snapshot().contents().contains("Message"));
    assert_no_network_attempt(&poison);
    session.reap();
    session.assert_reaped();
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
    let poison = install_poison_endpoints(&mut session);
    session.start_trusted_daemon();

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
    assert_no_network_attempt(&poison);
    assert!(
        !provider.captured().is_empty(),
        "scripted provider saw no successful turn"
    );
}
