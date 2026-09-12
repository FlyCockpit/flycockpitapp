//! Typed platform-contract stop record for issue #398.
//!
//! This test intentionally does not impersonate Windows conformance. The
//! documented candidate cannot preserve Cockpit's current unbounded Windows
//! subprocess routes, so creating a restricted token and proving only endpoint
//! denial would be misleading evidence. A later finite product resource model
//! must replace this test with the real temporary-object fixture described in
//! `../docs/windows-child-isolation-contract.md`. It is deliberately not a
//! conformance fixture: a partial restricted-token experiment cannot establish
//! a boundary that preserves the current subprocess contract.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequiredCapability {
    WindowsHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockedResourceClass {
    UnconfinedFilesystemAndDependencies,
    ConfiguredExecutableAndRuntime,
    TemporaryAndWorkspaceResources,
    PtyAndStandardIo,
    ConfiguredNetwork,
    NativeApprovalBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GateOutcome {
    Unavailable {
        capability: RequiredCapability,
    },
    Blocked {
        resources: Vec<BlockedResourceClass>,
    },
}

fn documented_outcome() -> GateOutcome {
    if !cfg!(windows) {
        return GateOutcome::Unavailable {
            capability: RequiredCapability::WindowsHost,
        };
    }

    GateOutcome::Blocked {
        resources: vec![
            BlockedResourceClass::UnconfinedFilesystemAndDependencies,
            BlockedResourceClass::ConfiguredExecutableAndRuntime,
            BlockedResourceClass::TemporaryAndWorkspaceResources,
            BlockedResourceClass::PtyAndStandardIo,
            BlockedResourceClass::ConfiguredNetwork,
            BlockedResourceClass::NativeApprovalBoundary,
        ],
    }
}

#[test]
fn platform_contract_fails_closed_until_every_current_route_has_a_finite_model() {
    let outcome = documented_outcome();

    eprintln!("Windows child-isolation documented stop outcome: {outcome:?}");

    if cfg!(windows) {
        assert_eq!(
            outcome,
            GateOutcome::Blocked {
                resources: vec![
                    BlockedResourceClass::UnconfinedFilesystemAndDependencies,
                    BlockedResourceClass::ConfiguredExecutableAndRuntime,
                    BlockedResourceClass::TemporaryAndWorkspaceResources,
                    BlockedResourceClass::PtyAndStandardIo,
                    BlockedResourceClass::ConfiguredNetwork,
                    BlockedResourceClass::NativeApprovalBoundary,
                ],
            },
            "the documented Windows gate must not convert an incomplete model into conformance evidence"
        );
    } else {
        assert_eq!(
            outcome,
            GateOutcome::Unavailable {
                capability: RequiredCapability::WindowsHost,
            },
            "non-Windows hosts must report an explicit unavailable state"
        );
    }
}

#[test]
fn platform_contract_records_the_stop_outcome_required_observations_and_all_routes() {
    let contract = include_str!("../docs/windows-child-isolation-contract.md");

    for required_text in [
        "**Status:** **Blocked — no production activation**",
        "CreateRestrictedToken",
        "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
        "bInheritHandles = FALSE",
        "PROCESS_DUP_HANDLE",
        "ordinary-current-user supervisor admission",
        "typed `Unavailable`",
        "#399 remains deferred",
        "test-only typed stop recorder, not a conformance fixture",
        "It deliberately does not create a Job, token, pipe, or\nprocess",
        "stop recorder must be replaced with a real temporary-object fixture",
        "It checks the status record\nand route-inventory parity only; it",
        "Foreground shell; background/adopted shell",
        "Custom tools; skill `!` interpolation",
        "Worker-owned terminal child",
        "Agent hooks",
        "Harness invocation; auth/model probes",
        "MCP stdio servers",
        "LSP servers and command actions",
        "Command-resource introspection",
        "Container runtime client",
        "Media/audio/video runners",
        "Native computer helpers",
        "Git/GitHub/worktree helpers",
        "`crates/cockpit-core/src/tools/bash/mod.rs`",
        "`apps/cli/src/terminal_host.rs`",
        "`crates/cockpit-core/src/container/mod.rs`",
        "`crates/cockpit-core/src/git/mod.rs`",
    ] {
        assert!(
            contract.contains(required_text),
            "platform contract lost required conformance gate: {required_text}"
        );
    }
}
