//! Linux native containment adapter.
//!
//! Backed by [`cockpit_host::process::ProcessTreeGuard`]: a fresh process
//! group prepared before spawn. The adapter allocates that guard and never
//! runs `req.program`. Callers spawn into the returned guard with
//! `process_group(0)`, prove membership with `getpgid` / `kill(-pgid, 0)`,
//! then terminate the group. This adapter never fabricates Proven from an
//! in-memory log or an absent cgroup broker.
//!
//! Off-Linux hosts return Unsupported.

use std::sync::Arc;

use async_trait::async_trait;
use cockpit_host::process::ProcessTreeGuard;

use super::adapter::{
    AdapterHandle, AllocatedContainment, ContainerExecRequest, ContainmentAdapter,
    NativeSpawnRequest, SharedAdapter,
};
use super::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, PlatformKind, SafeContainmentMetadata,
    SafeLocator,
};
use super::unix::{UnixHost, UnixProcessTreeAdapter, impl_unix_host_adapter};

/// Retained for fail-open fixtures that still model a missing cgroup broker.
pub const MANAGEMENT_BOUNDARY_UNAVAILABLE: &str = "management_boundary_unavailable";

pub use super::unix::{
    LINUX_PROCESS_TREE_UNAVAILABLE_ON_HOST, PROCESS_GROUP_EMPTY_MEMBERSHIP_UNPROVEN,
};

/// Linux native adapter: [`ProcessTreeGuard`] on Linux, Unsupported elsewhere.
pub struct LinuxCgroupAdapter(UnixProcessTreeAdapter);

impl LinuxCgroupAdapter {
    pub fn production() -> Self {
        Self(UnixProcessTreeAdapter::new(UnixHost::Linux))
    }

    #[cfg(test)]
    pub fn close_handles(&self, handle: &AdapterHandle) {
        self.0.close_handles(handle);
    }

    #[cfg(test)]
    pub fn order(&self) -> Vec<&'static str> {
        self.0.order()
    }

    #[cfg(all(test, target_os = "linux"))]
    fn live_group_count(&self) -> usize {
        self.0.live_group_count()
    }
}

impl_unix_host_adapter!(LinuxCgroupAdapter);

/// Select Linux native adapter or fall back to container adapter when Proven
/// native is unavailable.
#[allow(dead_code)]
pub fn select_linux_adapter(container: Option<SharedAdapter>) -> SharedAdapter {
    let linux = LinuxCgroupAdapter::production();
    if linux.guarantee() == ContainmentGuarantee::Proven {
        Arc::new(linux)
    } else if let Some(c) = container {
        c
    } else {
        Arc::new(linux)
    }
}

#[cfg(test)]
mod linux_process_tree_guard {
    use super::*;

    fn sleeper_request(generation: u64) -> NativeSpawnRequest {
        NativeSpawnRequest {
            containment_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            generation,
            operation_id: "op".into(),
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "sleep 30".into()],
            cwd: "/tmp".into(),
            require_proven: true,
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn create_and_spawn_allocates_guard_without_running_user_code() {
        use std::process::Stdio;

        let adapter = LinuxCgroupAdapter::production();
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Proven);
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        assert_eq!(allocated.guarantee, ContainmentGuarantee::Proven);
        assert!(adapter.order().contains(&"allocate_process_tree_guard"));

        let tree = adapter
            .process_tree_guard(&allocated.handle)
            .expect("allocated process-tree guard");
        assert!(
            !tree.group_is_bound(),
            "lease creation must not place a process"
        );
        match adapter
            .prove_membership(&allocated.handle, 1)
            .await
            .unwrap_err()
        {
            ContainmentError::DescendantContainmentUnavailable { reason } => {
                assert_eq!(reason, PROCESS_GROUP_EMPTY_MEMBERSHIP_UNPROVEN);
            }
            o => panic!("{o:?}"),
        }

        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        tree.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn process-group child");
        tree.assign(&child)
            .expect("record process-group membership");
        adapter
            .prove_membership(&allocated.handle, 1)
            .await
            .expect("kernel membership after assign");
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::Uncertain { reason, .. } => {
                assert_eq!(reason, "process_group_still_populated");
            }
            o => panic!("live group must not fabricate empty: {o:?}"),
        }
        tree.resume(&child).expect("unix resume is a no-op");

        adapter.terminate(&allocated.handle, 1).await.unwrap();
        let _ = child.wait().await;
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 1),
            o => panic!("{o:?}"),
        }
        assert_eq!(
            adapter.live_group_count(),
            0,
            "ProvenEmpty must reclaim the process-group guard"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn create_and_spawn_ignores_missing_user_program() {
        let adapter = LinuxCgroupAdapter::production();
        let allocated = adapter
            .create_and_spawn(NativeSpawnRequest {
                containment_id: uuid::Uuid::new_v4(),
                session_id: uuid::Uuid::new_v4(),
                generation: 1,
                operation_id: "op".into(),
                program: "/cockpit_missing_process_tree_probe".into(),
                args: vec![],
                cwd: "/tmp".into(),
                require_proven: true,
            })
            .await
            .expect("missing program must not be spawned at lease creation");
        assert_eq!(allocated.guarantee, ContainmentGuarantee::Proven);
        adapter.close_handles(&allocated.handle);
        assert!(adapter.order().contains(&"release_group"));
        assert_eq!(adapter.live_group_count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn production_adapter_is_proven_on_linux() {
        let adapter = LinuxCgroupAdapter::production();
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Proven);
        assert_eq!(adapter.platform_kind(), PlatformKind::LinuxProcessGroup);
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        assert_eq!(allocated.guarantee, ContainmentGuarantee::Proven);
        adapter.close_handles(&allocated.handle);
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn production_adapter_is_unsupported_off_linux() {
        let adapter = LinuxCgroupAdapter::production();
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Unsupported);
        assert_eq!(
            adapter.safe_metadata().capability_reason.as_deref(),
            Some(LINUX_PROCESS_TREE_UNAVAILABLE_ON_HOST)
        );
        let err = adapter
            .create_and_spawn(sleeper_request(1))
            .await
            .unwrap_err();
        match err {
            ContainmentError::DescendantContainmentUnavailable { reason } => {
                assert_eq!(reason, LINUX_PROCESS_TREE_UNAVAILABLE_ON_HOST);
            }
            o => panic!("{o:?}"),
        }
    }

    #[tokio::test]
    async fn daemon_death_missing_group_is_uncertain() {
        let adapter = LinuxCgroupAdapter::production();
        match adapter
            .recover(
                &SafeLocator {
                    locator_key: Some("pg-gone".into()),
                    ..Default::default()
                },
                3,
            )
            .await
            .unwrap()
        {
            EmptyOutcome::Uncertain { generation, reason } => {
                assert_eq!(generation, 3);
                assert_eq!(reason, "process_group_locator_not_reusable");
            }
            o => panic!("{o:?}"),
        }
    }
}
