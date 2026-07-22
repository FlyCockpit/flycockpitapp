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
