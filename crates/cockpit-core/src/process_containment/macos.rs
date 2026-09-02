//! macOS native containment adapter.
//!
//! Current supported macOS APIs provide no unprivileged kernel object that both
//! captures arbitrary reparented/session-escaping descendants and proves the set
//! empty. This adapter therefore returns Unsupported for Proven workflows.
//!
//! Process-group, kqueue, libproc polling, inherited-FD sentinels, launchd
//! heuristics, and shell syntax inspection are never labeled Proven.

use async_trait::async_trait;

use super::adapter::{
    AdapterHandle, AllocatedContainment, ContainerExecRequest, ContainmentAdapter,
    NativeSpawnRequest,
};
use super::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, PlatformKind, SafeContainmentMetadata,
    SafeLocator,
};

pub const MACOS_UNSUPPORTED_REASON: &str = "macos_no_unprivileged_descendant_container";

pub struct MacosNativeAdapter;

impl Default for MacosNativeAdapter {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl ContainmentAdapter for MacosNativeAdapter {
    fn platform_kind(&self) -> PlatformKind {
        PlatformKind::MacosUnsupported
    }

    fn guarantee(&self) -> ContainmentGuarantee {
        ContainmentGuarantee::Unsupported
    }

    fn safe_metadata(&self) -> SafeContainmentMetadata {
        SafeContainmentMetadata {
            platform_kind: PlatformKind::MacosUnsupported,
            guarantee: ContainmentGuarantee::Unsupported,
            capability_reason: Some(MACOS_UNSUPPORTED_REASON.into()),
            adapter_name: "macos_native_unsupported".into(),
            management_boundary: None,
        }
    }

    async fn probe(&self) -> Result<SafeContainmentMetadata, ContainmentError> {
        Ok(self.safe_metadata())
    }

    async fn create_and_spawn(
        &self,
        req: NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        // Fail before child creation / delegated child records.
        let _ = req;
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: MACOS_UNSUPPORTED_REASON.into(),
        })
    }

    async fn prove_membership(
        &self,
        _handle: &AdapterHandle,
        _generation: u64,
    ) -> Result<(), ContainmentError> {
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: MACOS_UNSUPPORTED_REASON.into(),
        })
    }

    async fn create_container_and_exec(
        &self,
        _req: ContainerExecRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        // Container path is a distinct adapter; native macOS does not implement it.
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: "macos_native_is_not_container_adapter".into(),
        })
    }

    async fn terminate(
        &self,
        _handle: &AdapterHandle,
        _generation: u64,
    ) -> Result<(), ContainmentError> {
        Ok(())
    }

    async fn await_empty(
        &self,
        _handle: &AdapterHandle,
        _generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        Ok(EmptyOutcome::Unsupported {
            reason: MACOS_UNSUPPORTED_REASON.into(),
        })
    }

    async fn recover(
        &self,
        _locator: &SafeLocator,
        _generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        Ok(EmptyOutcome::Unsupported {
            reason: MACOS_UNSUPPORTED_REASON.into(),
        })
    }
}

/// Heuristics that must never advertise Proven.
#[allow(dead_code)]
pub fn forbidden_proven_heuristics() -> &'static [&'static str] {
    &[
        "process_group",
        "kqueue",
        "libproc_polling",
        "inherited_fd_sentinel",
        "launchd_heuristic",
        "shell_syntax_inspection",
    ]
}

#[cfg(test)]
mod macos_proven_containment_is_honestly_unsupported {
    use super::*;

    #[tokio::test]
    async fn strict_native_fails_before_user_code() {
        let adapter = MacosNativeAdapter;
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Unsupported);
        let err = adapter
            .create_and_spawn(NativeSpawnRequest {
                containment_id: uuid::Uuid::new_v4(),
                session_id: uuid::Uuid::new_v4(),
                generation: 1,
                operation_id: "op".into(),
                program: "/bin/echo".into(),
                args: vec!["hello".into()],
                cwd: "/tmp".into(),
                require_proven: true,
            })
            .await
            .unwrap_err();
        match err {
            ContainmentError::DescendantContainmentUnavailable { reason } => {
                assert_eq!(reason, MACOS_UNSUPPORTED_REASON);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn no_heuristic_backend_advertises_proven() {
        for h in forbidden_proven_heuristics() {
            assert_ne!(*h, "proven");
        }
        let meta = MacosNativeAdapter.safe_metadata();
        assert_eq!(meta.guarantee, ContainmentGuarantee::Unsupported);
        assert!(meta.capability_reason.is_some());
    }
}
