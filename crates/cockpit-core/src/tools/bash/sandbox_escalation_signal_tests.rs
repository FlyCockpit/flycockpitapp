use super::*;

fn failed(stderr: &'static [u8]) -> ShellOutcome {
    ShellOutcome {
        stdout: Vec::new(),
        stderr: stderr.to_vec(),
        exit: 1,
        signaled: false,
        success: false,
    }
}

#[test]
fn fake_permission_stderr_does_not_offer_unconfined_rerun() {
    let outcome = failed(b"cat: /etc/secret: Permission denied\n");
    let mut meta = crate::engine::tool::SandboxMeta {
        enabled: true,
        confined: true,
        escalated: false,
        escalation_preauthorized: false,
        approval_scope_recorded: None,
        unavailable_reason: None,
        resource_profiles: Vec::new(),
    };

    if confined_failure_escalation_offer(&outcome).is_some() {
        meta.escalated = true;
    }

    assert!(!meta.escalated);
    assert!(confined_failure_escalation_offer(&outcome).is_none());
}

#[test]
fn fake_readonly_stderr_from_write_target_does_not_offer_rerun() {
    let outcome = failed(b"sh: cannot create outside.txt: Read-only file system\n");

    assert!(confined_failure_escalation_offer(&outcome).is_none());
}

#[test]
fn sandbox_failure_without_trusted_signal_keeps_actionable_result() {
    let tmp = tempfile::tempdir().unwrap();
    let outcome = failed(b"touch: cannot touch '/outside': Read-only file system\n");
    let body = render_output(
        &outcome,
        false,
        "touch /outside",
        tmp.path(),
        BashOutputAnnotations::default(),
    );

    assert!(confined_failure_escalation_offer(&outcome).is_none());
    assert!(body.contains("Read-only file system"));
    assert!(body.contains("exit: 1"));
}

fn line_index(lines: &[&str], prefix: &str) -> usize {
    lines
        .iter()
        .position(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("missing line prefix `{prefix}` in {lines:?}"))
}

#[test]
fn environment_block_reports_confinement() {
    let root = tempfile::tempdir().unwrap();
    let confined = cockpit_command_environment_block_with_requirements(
        "cargo test",
        root.path(),
        Some("2"),
        None,
        None,
        Some(true),
        Vec::new(),
    );
    let unconfined = cockpit_command_environment_block_with_requirements(
        "cargo test",
        root.path(),
        Some("2"),
        None,
        None,
        Some(false),
        Vec::new(),
    );
    let unknown = cockpit_command_environment_block_with_requirements(
        "cargo test",
        root.path(),
        Some("2"),
        None,
        None,
        None,
        Vec::new(),
    );
    let missing = cockpit_command_environment_block_with_requirements(
        "jq . package.json",
        root.path(),
        Some("127"),
        None,
        Some("jq"),
        Some(true),
        vec![crate::capabilities::BinaryRequirement::required(
            "jq",
            crate::capabilities::common_remedy("jq"),
        )],
    );

    assert!(confined.contains("confined: true\n"));
    assert!(unconfined.contains("confined: false\n"));
    assert!(!unknown.contains("confined:"));
    for block in [&confined, &missing] {
        let lines = block.lines().collect::<Vec<_>>();
        let exit_idx = line_index(&lines, "exit_code:");
        let confined_idx = line_index(&lines, "confined:");
        let diagnostic_idx = line_index(&lines, "diagnostic:");
        assert_eq!(confined_idx, exit_idx + 1, "{block}");
        assert!(confined_idx < diagnostic_idx, "{block}");
    }
}

#[test]
fn container_confined_failure_names_escalate_and_call_id() {
    let tmp = tempfile::tempdir().unwrap();
    let mut ctx = crate::tools::common::test_ctx(tmp.path());
    ctx.current_tool_call_id = Some("call-container".to_string());
    ctx.session.set_sandbox_escalation_enabled(true);
    let meta = crate::engine::tool::SandboxMeta {
        enabled: true,
        confined: true,
        escalated: false,
        escalation_preauthorized: false,
        approval_scope_recorded: None,
        unavailable_reason: None,
        resource_profiles: Vec::new(),
    };

    let out = render_bash_outcome(
        "printf blocked",
        tmp.path(),
        failed(b"blocked\n"),
        &ctx,
        meta,
        &None,
        None,
    );

    assert!(out.content.contains("call `escalate`"));
    assert!(out.content.contains("call_id=\"call-container\""));
    assert!(out.content.contains("confined: true"));
}
