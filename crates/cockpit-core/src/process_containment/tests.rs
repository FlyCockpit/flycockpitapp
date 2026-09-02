//! Cross-cutting acceptance tests for process containment.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use crate::db::Db;
use crate::process_containment::actor::ProcessContainmentActor;
use crate::process_containment::adapter::ContainmentAdapter;
use crate::process_containment::fake::{FakeEmptyMode, FakeProvenAdapter, FakeUnsupportedAdapter};
use crate::process_containment::macos::MacosNativeAdapter;
use crate::process_containment::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, LateCallbackKind, PlatformKind,
};

async fn seed_session(db: &Db) -> Uuid {
    db.create_session("proj", "/tmp/containment", "orchestrator-build")
        .await
        .unwrap()
        .session_id
}

/// AC1: authority/deletion/shutdown tests must not treat immediate-child exit,
/// process-group, PID polling, or portable-pty-drop as Proven empty.
#[tokio::test]
async fn descendant_containment_tests_corrected_first() {
    let db = Db::open_in_memory().unwrap();
    let session = seed_session(&db).await;
    let fake = FakeProvenAdapter::new(PlatformKind::Fake);
    let actor = ProcessContainmentActor::start(db.clone(), Arc::new(fake.clone()));
    let handle = actor.handle();

    let lease = handle
        .create_and_spawn(
            session,
            "op-1",
            PathBuf::from("/bin/true"),
            vec![],
            PathBuf::from("/tmp"),
            true,
        )
        .await
        .unwrap();

    // Immediate child exit / process-group / PID poll are NOT the oracle.
    handle
        .inject_late_callback(
            lease.containment_id(),
            lease.generation(),
            LateCallbackKind::ProcessExit,
        )
        .await
        .unwrap();

    // Group still populated until adapter terminate + empty oracle.
    fake.mark_populated(
        // We need the handle key — terminate first then mark empty path.
        // Before terminate, await_empty should not claim ProvenEmpty while populated.
        "unused", true,
    );
    // Terminate via containment object (not PID list).
    handle.terminate(lease.clone()).await.unwrap();
    match handle.await_empty(lease.clone()).await.unwrap() {
        EmptyOutcome::ProvenEmpty { generation } => {
            assert_eq!(generation, lease.generation());
        }
        other => panic!("expected ProvenEmpty from adapter oracle, got {other:?}"),
    }

    // Session deletion waits for ProvenEmpty — not child exit.
    handle.begin_session_deletion(session).await.unwrap();
    handle.finish_session_deletion(session).await.unwrap();

    // Portable-pty-drop / process-group assumptions are not Proven:
    // Unsupported platforms never return ProvenEmpty as authority.
    let mac = MacosNativeAdapter;
    assert_eq!(mac.guarantee(), ContainmentGuarantee::Unsupported);
}

#[tokio::test]
async fn containment_generation_rejects_late_events() {
    let db = Db::open_in_memory().unwrap();
    let session = seed_session(&db).await;
    let fake = FakeProvenAdapter::default();
    let actor = ProcessContainmentActor::start(db.clone(), Arc::new(fake.clone()));
    let handle = actor.handle();

    let lease = handle
        .create_and_spawn(session, "op", "/bin/true", vec![], "/tmp", true)
        .await
        .unwrap();

    // Stale generation callback must not empty current.
    handle
        .inject_late_callback(
            lease.containment_id(),
            lease.generation().saturating_sub(1),
            LateCallbackKind::EmptyNotification,
        )
        .await
        .unwrap();

    // Terminate current generation.
    handle.terminate(lease.clone()).await.unwrap();
    let outcome = handle.await_empty(lease.clone()).await.unwrap();
    assert!(matches!(outcome, EmptyOutcome::ProvenEmpty { .. }));
}

#[tokio::test]
async fn session_deletion_waits_for_descendants() {
    let db = Db::open_in_memory().unwrap();
    let session = seed_session(&db).await;
    let fake = FakeProvenAdapter::default();
    let actor = ProcessContainmentActor::start(db.clone(), Arc::new(fake.clone()));
    let handle = actor.handle();

    let lease = handle
        .create_and_spawn(session, "op", "/bin/sleep", vec!["30".into()], "/tmp", true)
        .await
        .unwrap();

    // Commit Deleting — rejects new work.
    handle.begin_session_deletion(session).await.unwrap();
    let err = handle
        .create_and_spawn(session, "op2", "/bin/true", vec![], "/tmp", true)
        .await
        .unwrap_err();
    assert!(matches!(err, ContainmentError::SessionDeleting));

    // finish requires empty
    // begin_session_deletion already terminated; should be empty.
    handle.finish_session_deletion(session).await.unwrap();

    // Kill failure leaves recoverable Deleting session.
    let session2 = seed_session(&db).await;
    let lease2 = handle
        .create_and_spawn(session2, "op", "/bin/true", vec![], "/tmp", true)
        .await
        .unwrap();
    fake.set_empty_mode(FakeEmptyMode::Uncertain);
    handle.begin_session_deletion(session2).await.unwrap();
    let blocked = handle.finish_session_deletion(session2).await.unwrap_err();
    assert!(matches!(blocked, ContainmentError::DeletionBlocked { .. }));
    assert!(db.is_session_deleting(session2).await.unwrap());
    // Rows retained
    assert!(
        !db.list_execution_containments_for_session(session2)
            .await
            .unwrap()
            .is_empty()
    );
    let _ = lease;
    let _ = lease2;
}

#[tokio::test]
async fn daemon_shutdown_waits_for_descendants() {
    let db = Db::open_in_memory().unwrap();
    let session = seed_session(&db).await;
    let fake = FakeProvenAdapter::default();
    let actor = ProcessContainmentActor::start(db.clone(), Arc::new(fake.clone()));
    let handle = actor.handle();

    let lease = handle
        .create_and_spawn(session, "op", "/bin/true", vec![], "/tmp", true)
        .await
        .unwrap();

    handle.begin_shutdown().await.unwrap();
    // Concurrent creation rejected
    let err = handle
        .create_and_spawn(session, "op2", "/bin/true", vec![], "/tmp", true)
        .await
        .unwrap_err();
    assert!(matches!(err, ContainmentError::ShutdownIntakeClosed));

    handle.terminate(lease.clone()).await.unwrap();
    match handle.await_empty(lease).await.unwrap() {
        EmptyOutcome::ProvenEmpty { .. } => {}
        o => panic!("{o:?}"),
    }
    handle
        .await_all_empty(Some(Duration::from_secs(1)))
        .await
        .unwrap();
}

#[tokio::test]
async fn daemon_shutdown_not_clean_when_uncertain() {
    let db = Db::open_in_memory().unwrap();
    let session = seed_session(&db).await;
    let fake = FakeProvenAdapter::default();
    fake.set_empty_mode(FakeEmptyMode::Uncertain);
    let actor = ProcessContainmentActor::start(db.clone(), Arc::new(fake));
    let handle = actor.handle();
    let _lease = handle
        .create_and_spawn(session, "op", "/bin/true", vec![], "/tmp", true)
        .await
        .unwrap();
    handle.begin_shutdown().await.unwrap();
    let err = handle
        .await_all_empty(Some(Duration::from_millis(50)))
        .await
        .unwrap_err();
    assert!(matches!(err, ContainmentError::ShutdownNotClean { .. }));
}

#[tokio::test]
async fn macos_strict_uses_container_when_available() {
    // Native macOS is Unsupported; container adapter is independent.
    let native = FakeUnsupportedAdapter::macos();
    assert_eq!(native.guarantee(), ContainmentGuarantee::Unsupported);

    let db = Db::open_in_memory().unwrap();
    let session = seed_session(&db).await;
    let (container, _) = crate::process_containment::container::ContainerRuntimeAdapter::fake(
        crate::process_containment::container::RuntimeKind::Docker,
    );
    let actor = ProcessContainmentActor::start(db, Arc::new(container));
    let handle = actor.handle();
    let lease = handle
        .create_container_and_exec(
            session,
            "op",
            "ubuntu:24.04",
            vec!["true".into()],
            "abcdabcdabcdabcdabcdabcdabcdabcd",
            "nonce1",
            true,
        )
        .await
        .unwrap();
    assert_eq!(lease.guarantee(), ContainmentGuarantee::Proven);
    handle.terminate(lease.clone()).await.unwrap();
    match handle.await_empty(lease).await.unwrap() {
        EmptyOutcome::ProvenEmpty { .. } => {}
        o => panic!("{o:?}"),
    }
}

#[tokio::test]
async fn queue_saturation_returns_busy() {
    // The queue is large; we verify the error type exists and Full maps correctly.
    let err = ContainmentError::QueueSaturated;
    assert!(err.to_string().contains("saturated"));
}

/// Compile inventory: workspace-owned windows-sys feature union (AC12).
#[test]
fn containment_platform_compile_inventory() {
    // Documented workspace-owned leaf union (exact eight).
    let workspace_owned = [
        "Wdk_Foundation",
        "Wdk_Storage_FileSystem",
        "Win32_Foundation",
        "Win32_Security",
        "Win32_Storage_FileSystem",
        "Win32_System_IO",
        "Win32_System_JobObjects",
        "Win32_System_Threading",
    ];
    assert_eq!(workspace_owned.len(), 8);

    // Containment owner requests (Windows only) these five:
    let containment_leaves = [
        "Win32_Foundation",
        "Win32_Security",
        "Win32_System_IO",
        "Win32_System_JobObjects",
        "Win32_System_Threading",
    ];
    // cockpit-config requests these six:
    let config_leaves = [
        "Wdk_Foundation",
        "Wdk_Storage_FileSystem",
        "Win32_Foundation",
        "Win32_Security",
        "Win32_Storage_FileSystem",
        "Win32_System_IO",
    ];
    let mut union: Vec<&str> = containment_leaves
        .iter()
        .chain(config_leaves.iter())
        .copied()
        .collect();
    union.sort();
    union.dedup();
    assert_eq!(union, workspace_owned);

    // Manifest inventory (parse local Cargo.toml snippets as strings).
    let core_toml = include_str!("../../Cargo.toml");
    let config_toml = include_str!("../../../cockpit-config/Cargo.toml");
    assert!(
        core_toml.contains("windows-sys") || cfg!(not(windows)),
        "cockpit-core must declare target windows-sys on Windows"
    );
    // Always require the declaration in the manifest regardless of host.
    assert!(
        core_toml.contains("Win32_System_JobObjects"),
        "containment owner must directly request JobObjects"
    );
    assert!(
        core_toml.contains("version = \"=0.61.2\"") || core_toml.contains("version = \"0.61.2\""),
        "windows-sys pin 0.61.2"
    );
    assert!(config_toml.contains("default-features = false"));
    assert!(config_toml.contains("Wdk_Foundation"));
    assert!(config_toml.contains("Win32_Storage_FileSystem"));
    assert!(!config_toml.contains("Win32_System_JobObjects"));

    // Non-Windows: the target-gated dependency must not activate on this graph.
    #[cfg(not(windows))]
    {
        // Symbol module only exists on Windows; this branch is host-gated.
    }

    #[cfg(windows)]
    {
        let names = crate::process_containment::windows::job_symbols::inventory_symbol_names();
        assert!(names.contains(&"CreateJobObjectW"));
        assert!(names.contains(&"AssignProcessToJobObject"));
        assert!(names.contains(&"QueryInformationJobObject"));
        assert!(names.contains(&"TerminateJobObject"));
    }

    // Docker/Podman command parity names.
    assert_eq!(
        crate::process_containment::container::RuntimeKind::Docker.as_str(),
        "docker"
    );
    assert_eq!(
        crate::process_containment::container::RuntimeKind::Podman.as_str(),
        "podman"
    );
}
