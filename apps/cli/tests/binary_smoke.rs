mod support;

use std::io::Write;
use std::process::Stdio;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use support::{IsolatedHome, assert_failure, output_text};

#[test]
fn help_runs_from_built_binary() {
    let home = IsolatedHome::new();

    home.cockpit()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("AI coding harness"));
}

#[test]
fn bad_flag_returns_usage_error() {
    let home = IsolatedHome::new();
    let output = home
        .cockpit()
        .arg("--definitely-not-a-real-flag")
        .output()
        .expect("run bad flag");

    assert_failure("cockpit --definitely-not-a-real-flag", &output, &home);
    assert_eq!(output.status.code(), Some(2));
    assert!(output_text(&output).contains("unexpected argument"));
    assert!(output_text(&output).contains("Usage:"));
}

#[test]
fn run_ephemeral_reads_stdin_and_enters_non_interactive_one_shot_mode() {
    let home = IsolatedHome::new();
    let trust = home
        .cockpit()
        .args([
            "trust",
            "set",
            home.project_path().to_str().expect("utf-8 project path"),
            "--mode",
            "trust",
        ])
        .output()
        .expect("seed workspace trust");
    assert!(trust.status.success(), "{}", output_text(&trust));

    let mut cmd = home.cockpit();
    cmd.args(["run", "--ephemeral"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn one-shot command");
    child
        .stdin
        .as_mut()
        .expect("one-shot stdin")
        .write_all(b"smoke prompt")
        .expect("write one-shot stdin");
    let output = child.wait_with_output().expect("run one-shot command");

    assert_failure("cockpit run --ephemeral", &output, &home);
    let text = output_text(&output);
    assert!(
        text.contains("timed out waiting for daemon")
            || text.contains("model")
            || text.contains("provider"),
        "{text}"
    );
}

#[test]
fn daemon_status_is_isolated_to_test_home() {
    let home = IsolatedHome::new();

    home.cockpit()
        .args(["daemon", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("canonical daemon not running"));
}
