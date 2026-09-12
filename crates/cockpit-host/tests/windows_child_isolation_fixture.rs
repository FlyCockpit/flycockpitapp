//! Manual stop-record runner for issue #398.
//!
//! This test intentionally does not impersonate Windows conformance. The
//! documented candidate cannot preserve Cockpit's current unbounded Windows
//! subprocess routes, so creating a restricted token and proving only endpoint
//! denial would be misleading evidence. A later finite product resource model
//! must replace this test with the real temporary-object fixture described in
//! `../docs/windows-child-isolation-contract.md`.

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
enum FixtureOutcome {
    Unavailable {
        capability: RequiredCapability,
    },
    Blocked {
        resources: Vec<BlockedResourceClass>,
    },
}

fn current_outcome() -> FixtureOutcome {
    if !cfg!(windows) {
        return FixtureOutcome::Unavailable {
            capability: RequiredCapability::WindowsHost,
        };
    }

    FixtureOutcome::Blocked {
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
fn conformance_runner_fails_closed_until_every_current_route_has_a_finite_model() {
    let outcome = current_outcome();

    if cfg!(windows) {
        assert_eq!(
            outcome,
            FixtureOutcome::Blocked {
                resources: vec![
                    BlockedResourceClass::UnconfinedFilesystemAndDependencies,
                    BlockedResourceClass::ConfiguredExecutableAndRuntime,
                    BlockedResourceClass::TemporaryAndWorkspaceResources,
                    BlockedResourceClass::PtyAndStandardIo,
                    BlockedResourceClass::ConfiguredNetwork,
                    BlockedResourceClass::NativeApprovalBoundary,
                ],
            },
            "a Windows host must not convert an incomplete model into conformance evidence"
        );
    } else {
        assert_eq!(
            outcome,
            FixtureOutcome::Unavailable {
                capability: RequiredCapability::WindowsHost,
            },
            "non-Windows hosts must report an explicit unavailable state"
        );
    }
}

#[test]
fn platform_contract_records_the_stop_outcome_and_required_real_observations() {
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
    ] {
        assert!(
            contract.contains(required_text),
            "platform contract lost required conformance gate: {required_text}"
        );
    }
}
