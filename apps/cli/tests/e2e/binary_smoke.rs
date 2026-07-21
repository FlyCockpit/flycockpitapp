use std::io::Write;
use std::process::Command;
use std::process::Stdio;

use crate::support::{IsolatedHome, assert_failure, output_text};
use assert_cmd::prelude::*;
use predicates::prelude::*;

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

#[test]
fn jq_applet_supports_common_flags_and_bindings() {
    let home = IsolatedHome::new();

    let array = home.project_path().join("array.json");
    std::fs::write(&array, r#"{"a":[1,2]}"#).unwrap();
    home.cockpit()
        .args(["jq", ".a[1]", array.to_str().unwrap()])
        .assert()
        .success()
        .stdout("2\n");

    home.cockpit()
        .args(["jq", "-n", "-r", "--arg", "name", "Ada", "$name"])
        .assert()
        .success()
        .stdout("Ada\n");

    home.cockpit()
        .args(["jq", "-n", "-c", "--argjson", "obj", r#"{"n":2}"#, "$obj.n"])
        .assert()
        .success()
        .stdout("2\n");

    let input = home.project_path().join("values.json");
    std::fs::write(&input, r#"{"n":1}{"n":2}"#).unwrap();
    home.cockpit()
        .args(["jq", "-s", "-c", "map(.n)", input.to_str().unwrap()])
        .assert()
        .success()
        .stdout("[1,2]\n");

    let slurp = home.project_path().join("slurp.json");
    std::fs::write(&slurp, r#"{"v":3}{"v":4}"#).unwrap();
    home.cockpit()
        .args([
            "jq",
            "-n",
            "-c",
            "--slurpfile",
            "data",
            slurp.to_str().unwrap(),
            "$data | map(.v)",
        ])
        .assert()
        .success()
        .stdout("[3,4]\n");

    let filter = home.project_path().join("filter.jq");
    std::fs::write(&filter, r#""x", "y""#).unwrap();
    home.cockpit()
        .args(["jq", "-n", "-j", "-f", filter.to_str().unwrap()])
        .assert()
        .success()
        .stdout("xy");

    home.cockpit()
        .args(["jq", "-n", "-e", "empty"])
        .assert()
        .code(4);

    home.cockpit()
        .args(["jq", "-n", "-e", "null"])
        .assert()
        .code(1);

    home.cockpit()
        .args(["jq", "-n", "-e", "false"])
        .assert()
        .code(1);

    home.cockpit()
        .args(["jq", "-n", "--indent", "4", r#"{"a":1}"#])
        .assert()
        .success()
        .stdout(predicate::str::contains("    \"a\""));

    home.cockpit()
        .args(["jq", "-n", "--tab", r#"{"a":1}"#])
        .assert()
        .success()
        .stdout(predicate::str::contains("\t\"a\""));
}

#[test]
fn jq_applet_identifies_bundled_implementation() {
    let home = IsolatedHome::new();

    home.cockpit()
        .args(["jq", "--version"])
        .assert()
        .success()
        .stdout(predicate::str::contains("jaq"))
        .stdout(predicate::str::contains("cockpit-bundled"))
        .stdout(predicate::str::contains("jq-compatible"))
        .stdout(predicate::str::starts_with("jq-").not());
}

#[test]
fn jq_applet_help_does_not_catalog_divergences() {
    let home = IsolatedHome::new();

    home.cockpit()
        .args(["jq", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage: cockpit jq"))
        .stdout(predicate::str::contains("diverg").not())
        .stdout(predicate::str::contains("NaN").not());
}

#[test]
fn jq_applet_rejects_unsupported_flags_explicitly() {
    let home = IsolatedHome::new();

    for flag in [
        "-a",
        "--stream",
        "--seq",
        "--jsonargs",
        "--unbuffered",
        "--stream-errors",
    ] {
        home.cockpit()
            .args(["jq", flag, "."])
            .assert()
            .failure()
            .stderr(predicate::str::contains(flag))
            .stderr(predicate::str::contains("cockpit-bundled"));
    }
}

#[test]
fn jq_argv0_dispatch_runs_before_clap() {
    let home = IsolatedHome::new();
    home.cockpit()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("AI coding harness"));

    let temp = tempfile::tempdir().unwrap();
    let target = assert_cmd::cargo::cargo_bin("cockpit");
    let jq = temp
        .path()
        .join(if cfg!(windows) { "jq.exe" } else { "jq" });
    link_test_binary(&target, &jq);

    Command::new(&jq)
        .args(["-n", "-r", r#""ok""#])
        .assert()
        .success()
        .stdout("ok\n");

    let other = temp
        .path()
        .join(if cfg!(windows) { "notjq.exe" } else { "notjq" });
    link_test_binary(&target, &other);
    Command::new(&other)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("AI coding harness"));
}

#[cfg(unix)]
fn link_test_binary(target: &std::path::Path, link: &std::path::Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(not(unix))]
fn link_test_binary(target: &std::path::Path, link: &std::path::Path) {
    std::fs::hard_link(target, link)
        .or_else(|_| std::fs::copy(target, link).map(|_| ()))
        .unwrap();
}
