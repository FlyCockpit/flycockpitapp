//! Executable release acceptance for a fresh, offline, no-account install.

use std::process::{Command, Output};
use std::{net::TcpListener, time::Duration};

use crate::support::{HermeticCockpit, HermeticProfile, output_text};

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
    let completion = run(&session, &["completion", "bash"]);
    assert!(completion.status.success(), "{}", output_text(&completion));
    let completion = output_text(&completion);
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
    let (poison, poison_env) = poison_flycockpit_endpoints(&session);
    let doctor = run_with_env(&session, &["doctor", "--offline"], poison_env);
    assert!(doctor.status.success(), "{}", output_text(&doctor));
    let models = run(&session, &["models"]);
    assert!(
        models.status.success() || models.status.code() == Some(4),
        "{}",
        output_text(&models)
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

#[test]
fn isolated_settings_export_and_restart_resume_paths_execute_without_accounts() {
    let mut session = HermeticCockpit::prepare(HermeticProfile::Default);
    session.enable_isolated_secret_service();
    session.start_trusted_daemon();
    session.spawn_pty(100, 30).unwrap();
    session.wait_until_ready(Duration::from_secs(30)).unwrap();

    let policy = session.project_path().join("portable-policy.json");
    let export = session.project_path().join("session-export.zip");
    let policy_text = policy.to_string_lossy().into_owned();
    let export_text = export.to_string_lossy().into_owned();
    for args in [
        vec!["config", "export-policy", "--output", &policy_text],
        vec!["config", "import-policy", &policy_text, "--replace"],
        vec!["session", "list"],
        vec!["export", "--output", &export_text],
        vec!["daemon", "restart"],
        vec!["daemon", "status"],
        vec!["session", "list"],
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
}
