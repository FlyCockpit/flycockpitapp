//! Process-boundary exit-code enforcement for the `tenant-authority` binary.
//!
//! Spawns the built binary via `CARGO_BIN_EXE_tenant-authority` and asserts
//! every subcommand surface fails closed with a non-zero exit. Test names
//! intentionally avoid the `tenant_authority_` prefix reserved for the nine
//! acceptance suites in `tenant_authority_service_acceptance.rs`.

fn tenant_authority_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_tenant-authority"))
}

fn run_tenant_authority(args: &[&str]) -> std::process::Output {
    std::process::Command::new(tenant_authority_bin())
        .args(args)
        .output()
        .expect("failed to spawn tenant-authority binary")
}

fn assert_exits_failure(label: &str, args: &[&str]) {
    let output = run_tenant_authority(args);
    assert!(
        !output.status.success(),
        "{label}: expected non-zero exit, got {:?}",
        output.status.code()
    );
}

#[test]
fn binary_exit_default_and_serve_nonzero() {
    assert_exits_failure("default (serve)", &[]);
    assert_exits_failure("explicit serve", &["serve"]);

    let output = run_tenant_authority(&["serve"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    #[cfg(unix)]
    assert!(
        stderr.contains("not implemented"),
        "serve stderr should mention not implemented: {stderr}"
    );
    #[cfg(not(unix))]
    assert!(
        stderr.contains("unsupported platform"),
        "serve stderr should mention unsupported platform: {stderr}"
    );
}

#[test]
fn binary_exit_offline_subcommands_nonzero() {
    for sub in [
        "bootstrap",
        "prepare-policy-revision",
        "prepare-authority-rotation",
        "replica",
    ] {
        assert_exits_failure(sub, &[sub]);
        let output = run_tenant_authority(&[sub]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("not implemented"),
            "{sub} stderr should mention not implemented: {stderr}"
        );
    }
}

#[test]
fn binary_exit_unknown_subcommand_nonzero() {
    assert_exits_failure("unknown subcommand", &["definitely-not-a-subcommand"]);
    let output = run_tenant_authority(&["definitely-not-a-subcommand"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown subcommand"),
        "stderr should mention unknown subcommand: {stderr}"
    );
}
