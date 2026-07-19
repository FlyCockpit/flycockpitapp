use super::*;

#[test]
fn windows_notice_fires_once_then_silent() {
    let tmp = tempfile::tempdir().unwrap();
    let ctx = crate::tools::common::test_ctx(tmp.path());
    // test_ctx defaults sandbox OFF → no notice.
    assert!(windows_shell_notice(&ctx).is_none());
    // With sandbox requested ON, the notice fires once, then the
    // one-shot guard silences it (process-global).
    ctx.session.set_sandbox_enabled(true);
    let first = windows_shell_notice(&ctx);
    let second = windows_shell_notice(&ctx);
    // Exactly one of the two is `Some` (whichever observed the guard
    // first); the other is `None`. (Other tests in this binary may
    // have tripped the guard already, so we assert "at most one.")
    assert!(first.is_none() || second.is_none());
    // And shell sandboxing is reported unsupported on Windows.
    assert!(!crate::tools::shell_sandbox::shell_sandbox_supported());
}
