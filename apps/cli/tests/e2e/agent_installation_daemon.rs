//! Transport-boundary regression coverage for daemon-owned agent installation.
//!
//! The complete daemon service state-machine tests live in `cockpit-core`.
//! This e2e target freezes the CLI-side rule that client code only creates
//! typed requests and renders typed outcomes; it never receives a credential
//! or writes an agent file directly.

#[test]
fn agent_installation_daemon_cli_transport_never_performs_direct_agent_mutation() {
    let source = include_str!("../../src/commands/agent.rs")
        .split("#[cfg(test)]")
        .next()
        .expect("production CLI source");
    assert!(source.contains("Request::AgentInstallationBegin"));
    assert!(source.contains("Request::AgentInstallationSubmitChoice"));
    assert!(source.contains("Request::AgentInstallationList"));
    assert!(source.contains("Request::AgentInstallationInspect"));
    assert!(!source.contains("std::fs::write"));
    assert!(!source.contains("std::fs::rename"));
    assert!(!source.contains("CredentialStore"));
    assert!(!source.contains("path.is_dir()"));
    assert!(!source.contains("path.file_stem()"));
    assert!(!source.contains("path.extension()"));
}
