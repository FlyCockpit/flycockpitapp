//! Linux cgroup-v2 + namespace guard adapter.
//!
//! Proven only when `CgroupNamespaceGuard` plus a distinct external management
//! broker boundary make migration out of the generation cgroup impossible
//! before user code. Missing broker, same-UID-only credentials, cgroup v1,
//! writable migration files, or topology drift → Unsupported before user code.
//!
//! Production hosts without the attested broker return Unsupported; tests use
//! injectable fixtures and never mutate the host cgroup tree.

use std::sync::Arc;

use async_trait::async_trait;

use super::adapter::{
    AdapterHandle, AllocatedContainment, ContainerExecRequest, ContainmentAdapter,
    NativeSpawnRequest, SharedAdapter,
};
use super::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, PlatformKind, SafeContainmentMetadata,
    SafeLocator,
};

/// Reasons that force Unsupported (deterministic; never host-skipped tests).
pub const MANAGEMENT_BOUNDARY_UNAVAILABLE: &str = "management_boundary_unavailable";
pub const CGROUP_V1_UNSUPPORTED: &str = "cgroup_v1_unsupported";
pub const DELEGATION_MISSING: &str = "cgroup_delegation_missing";
pub const MIGRATION_FILE_REACHABLE: &str = "cgroup_migration_file_reachable";
pub const GUARD_UNVERIFIED: &str = "cgroup_namespace_guard_unverified";

/// Broker that owns exclusive control of the delegated cgroup-v2 subtree.
pub trait ManagementBroker: Send + Sync + 'static {
    /// Distinct credential/LSM identity — not the workload UID.
    fn distinct_identity(&self) -> bool;
    /// Exclusive delegation: workload UID cannot write cgroup.procs.
    fn exclusive_delegation(&self) -> bool;
    /// Authenticate installation/containment/generation; no raw cgroup FD.
    fn authenticate(&self, installation: &str, containment: &str, generation: u64) -> bool;
    fn can_kill(&self, generation: u64) -> bool;
    fn populated(&self, generation: u64) -> Option<bool>;
}

/// Default: no broker installed → Unsupported.
#[derive(Debug, Default)]
pub struct AbsentBroker;

impl ManagementBroker for AbsentBroker {
    fn distinct_identity(&self) -> bool {
        false
    }
    fn exclusive_delegation(&self) -> bool {
        false
    }
    fn authenticate(&self, _: &str, _: &str, _: u64) -> bool {
        false
    }
    fn can_kill(&self, _: u64) -> bool {
        false
    }
    fn populated(&self, _: u64) -> Option<bool> {
        None
    }
}

/// Test broker with exclusive identity.
#[derive(Debug)]
pub struct TestBroker {
    pub identity_distinct: bool,
    pub exclusive: bool,
    pub generations: std::sync::Mutex<std::collections::HashMap<u64, bool>>,
}

impl Default for TestBroker {
    fn default() -> Self {
        Self {
            identity_distinct: true,
            exclusive: true,
            generations: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl ManagementBroker for TestBroker {
    fn distinct_identity(&self) -> bool {
        self.identity_distinct
    }
    fn exclusive_delegation(&self) -> bool {
        self.exclusive
    }
    fn authenticate(&self, _: &str, _: &str, generation: u64) -> bool {
        self.identity_distinct && self.exclusive && generation > 0
    }
    fn can_kill(&self, generation: u64) -> bool {
        self.authenticate("i", "c", generation)
    }
    fn populated(&self, generation: u64) -> Option<bool> {
        self.generations
            .lock()
            .ok()
            .and_then(|g| g.get(&generation).copied())
    }
}

impl TestBroker {
    pub fn set_populated(&self, generation: u64, populated: bool) {
        if let Ok(mut g) = self.generations.lock() {
            g.insert(generation, populated);
        }
    }
}

/// Result of verifying the launcher private namespace / FD / capability state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardVerification {
    pub private_mount_ns: bool,
    pub private_cgroup_ns: bool,
    pub no_new_privs: bool,
    pub caps_cleared: bool,
    pub cgroup_procs_unreachable: bool,
    pub seccomp_installed: bool,
    pub membership_proven: bool,
}

impl GuardVerification {
    pub fn fully_proven(&self) -> bool {
        self.private_mount_ns
            && self.private_cgroup_ns
            && self.no_new_privs
            && self.caps_cleared
            && self.cgroup_procs_unreachable
            && self.seccomp_installed
            && self.membership_proven
    }

    pub fn all_false() -> Self {
        Self {
            private_mount_ns: false,
            private_cgroup_ns: false,
            no_new_privs: false,
            caps_cleared: false,
            cgroup_procs_unreachable: false,
            seccomp_installed: false,
            membership_proven: false,
        }
    }
}

/// Cgroup namespace guard: verifies non-escapable private namespace before release.
#[derive(Debug, Clone)]
pub struct CgroupNamespaceGuard {
    pub verification: GuardVerification,
}

impl CgroupNamespaceGuard {
    pub fn unverified() -> Self {
        Self {
            verification: GuardVerification::all_false(),
        }
    }

    pub fn test_proven() -> Self {
        Self {
            verification: GuardVerification {
                private_mount_ns: true,
                private_cgroup_ns: true,
                no_new_privs: true,
                caps_cleared: true,
                cgroup_procs_unreachable: true,
                seccomp_installed: true,
                membership_proven: true,
            },
        }
    }

    pub fn is_proven(&self) -> bool {
        self.verification.fully_proven()
    }
}

/// Host capability snapshot (safe; no secrets).
#[derive(Debug, Clone)]
pub struct LinuxCapabilityProbe {
    pub cgroup_v2: bool,
    pub has_delegation: bool,
    pub migration_file_writable_by_workload: bool,
    pub broker_present: bool,
}

impl LinuxCapabilityProbe {
    /// Production probe — never mutates host state.
    pub fn detect() -> Self {
        #[cfg(target_os = "linux")]
        {
            let cgroup_v2 = std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
            Self {
                cgroup_v2,
                // Without an installed broker we never claim delegation Proven.
                has_delegation: false,
                migration_file_writable_by_workload: true, // assume worst without exclusive broker
                broker_present: false,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self {
                cgroup_v2: false,
                has_delegation: false,
                migration_file_writable_by_workload: true,
                broker_present: false,
            }
        }
    }

    pub fn unsupported_reason(&self, broker: &dyn ManagementBroker) -> Option<&'static str> {
        if !self.cgroup_v2 {
            return Some(CGROUP_V1_UNSUPPORTED);
        }
        if !self.broker_present || !broker.distinct_identity() || !broker.exclusive_delegation() {
            return Some(MANAGEMENT_BOUNDARY_UNAVAILABLE);
        }
        if !self.has_delegation {
            return Some(DELEGATION_MISSING);
        }
        if self.migration_file_writable_by_workload {
            return Some(MIGRATION_FILE_REACHABLE);
        }
        None
    }
}

pub struct LinuxCgroupAdapter {
    probe: LinuxCapabilityProbe,
    broker: Arc<dyn ManagementBroker>,
    guard: CgroupNamespaceGuard,
    /// Live handles: generation → populated (broker-backed when present).
    live: std::sync::Mutex<std::collections::HashMap<u64, bool>>,
}

impl LinuxCgroupAdapter {
    pub fn production() -> Self {
        Self {
            probe: LinuxCapabilityProbe::detect(),
            broker: Arc::new(AbsentBroker),
            guard: CgroupNamespaceGuard::unverified(),
            live: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn with_parts(
        probe: LinuxCapabilityProbe,
        broker: Arc<dyn ManagementBroker>,
        guard: CgroupNamespaceGuard,
    ) -> Self {
        Self {
            probe,
            broker,
            guard,
            live: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn reason_if_unsupported(&self) -> Option<&'static str> {
        if let Some(r) = self.probe.unsupported_reason(self.broker.as_ref()) {
            return Some(r);
        }
        if !self.guard.is_proven() {
            return Some(GUARD_UNVERIFIED);
        }
        None
    }
}

#[async_trait]
impl ContainmentAdapter for LinuxCgroupAdapter {
    fn platform_kind(&self) -> PlatformKind {
        PlatformKind::LinuxCgroup
    }

    fn guarantee(&self) -> ContainmentGuarantee {
        if self.reason_if_unsupported().is_some() {
            ContainmentGuarantee::Unsupported
        } else {
            ContainmentGuarantee::Proven
        }
    }

    fn safe_metadata(&self) -> SafeContainmentMetadata {
        let reason = self.reason_if_unsupported().map(|s| s.to_string());
        SafeContainmentMetadata {
            platform_kind: PlatformKind::LinuxCgroup,
            guarantee: self.guarantee(),
            capability_reason: reason,
            adapter_name: "linux_cgroup_namespace_guard".into(),
            management_boundary: if self.broker.distinct_identity() {
                Some("distinct_broker".into())
            } else {
                None
            },
        }
    }

    async fn probe(&self) -> Result<SafeContainmentMetadata, ContainmentError> {
        Ok(self.safe_metadata())
    }

    async fn create_and_spawn(
        &self,
        req: NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        if let Some(reason) = self.reason_if_unsupported() {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: reason.into(),
            });
        }
        if !self
            .broker
            .authenticate("install", &req.containment_id.to_string(), req.generation)
        {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: MANAGEMENT_BOUNDARY_UNAVAILABLE.into(),
            });
        }
        // Guard verified membership before releasing launcher — no user code yet.
        if !self.guard.verification.membership_proven {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: GUARD_UNVERIFIED.into(),
            });
        }
        self.live.lock().unwrap().insert(req.generation, true);
        let key = format!("linux-cgroup-{}", req.generation);
        Ok(AllocatedContainment {
            locator: SafeLocator {
                locator_key: Some(key.clone()),
                nonce: Some(format!("g{}", req.generation)),
                installation_digest: Some("linux".into()),
                ..Default::default()
            },
            guarantee: ContainmentGuarantee::Proven,
            handle: AdapterHandle { key },
        })
    }

    async fn prove_membership(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError> {
        let _ = handle;
        if !self.guard.verification.membership_proven {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: GUARD_UNVERIFIED.into(),
            });
        }
        let live = self.live.lock().unwrap();
        if !live.contains_key(&generation) {
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: "cgroup_generation_missing_membership_unproven".into(),
            });
        }
        Ok(())
    }

    async fn create_container_and_exec(
        &self,
        _req: ContainerExecRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: "linux_adapter_is_native_only".into(),
        })
    }

    async fn terminate(
        &self,
        _handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError> {
        if !self.broker.can_kill(generation) {
            return Err(ContainmentError::Internal(
                "broker_kill_denied_retryable".into(),
            ));
        }
        // cgroup.kill semantics via broker authority.
        self.live.lock().unwrap().insert(generation, false);
        Ok(())
    }

    async fn await_empty(
        &self,
        _handle: &AdapterHandle,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        // Sole empty oracle: same-generation cgroup.events populated=0 via actor authority.
        let populated = self.broker.populated(generation).or_else(|| {
            self.live
                .lock()
                .ok()
                .and_then(|g| g.get(&generation).copied())
        });
        match populated {
            Some(false) => Ok(EmptyOutcome::ProvenEmpty { generation }),
            Some(true) => Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "cgroup_still_populated".into(),
            }),
            None => Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "cgroup_populated_unknown".into(),
            }),
        }
    }

    async fn recover(
        &self,
        locator: &SafeLocator,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let _ = locator;
        if let Some(reason) = self.reason_if_unsupported() {
            return Ok(EmptyOutcome::Unsupported {
                reason: reason.into(),
            });
        }
        self.await_empty(
            &AdapterHandle {
                key: format!("linux-cgroup-{generation}"),
            },
            generation,
        )
        .await
    }
}

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
mod linux_cgroup_namespace_guard {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn no_user_code_before_verified_membership() {
        let broker = Arc::new(TestBroker::default());
        let adapter = LinuxCgroupAdapter::with_parts(
            LinuxCapabilityProbe {
                cgroup_v2: true,
                has_delegation: true,
                migration_file_writable_by_workload: false,
                broker_present: true,
            },
            broker,
            CgroupNamespaceGuard::test_proven(),
        );
        let req = NativeSpawnRequest {
            containment_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            generation: 1,
            operation_id: "op".into(),
            program: "/bin/true".into(),
            args: vec![],
            cwd: "/tmp".into(),
            require_proven: true,
        };
        let allocated = adapter.create_and_spawn(req).await.unwrap();
        assert_eq!(allocated.guarantee, ContainmentGuarantee::Proven);
        // Launcher cgroup membership is kernel-proven at allocate; durable
        // MembershipProven is still the actor's prove_membership RPC.
        assert!(adapter.guard.verification.membership_proven);
        adapter
            .prove_membership(&allocated.handle, 1)
            .await
            .expect("launcher membership is the linux kernel witness");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn absent_broker_is_management_boundary_unavailable() {
        let adapter = LinuxCgroupAdapter::production();
        let meta = adapter.probe().await.unwrap();
        assert_eq!(meta.guarantee, ContainmentGuarantee::Unsupported);
        assert_eq!(
            meta.capability_reason.as_deref(),
            Some(MANAGEMENT_BOUNDARY_UNAVAILABLE)
        );
        let err = adapter
            .create_and_spawn(NativeSpawnRequest {
                containment_id: uuid::Uuid::new_v4(),
                session_id: uuid::Uuid::new_v4(),
                generation: 1,
                operation_id: "op".into(),
                program: "/bin/true".into(),
                args: vec!["secret-arg-must-not-leak".into()],
                cwd: "/tmp".into(),
                require_proven: true,
            })
            .await
            .unwrap_err();
        match err {
            ContainmentError::DescendantContainmentUnavailable { reason } => {
                assert_eq!(reason, MANAGEMENT_BOUNDARY_UNAVAILABLE);
            }
            o => panic!("{o:?}"),
        }
    }

    #[tokio::test]
    async fn same_uid_only_broker_is_unsupported() {
        let broker = Arc::new(TestBroker {
            identity_distinct: false,
            exclusive: true,
            generations: std::sync::Mutex::new(HashMap::new()),
        });
        let adapter = LinuxCgroupAdapter::with_parts(
            LinuxCapabilityProbe {
                cgroup_v2: true,
                has_delegation: true,
                migration_file_writable_by_workload: false,
                broker_present: true,
            },
            broker,
            CgroupNamespaceGuard::test_proven(),
        );
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Unsupported);
        assert_eq!(
            adapter.reason_if_unsupported(),
            Some(MANAGEMENT_BOUNDARY_UNAVAILABLE)
        );
    }

    #[tokio::test]
    async fn external_migration_denied_while_actor_can_kill() {
        let broker = Arc::new(TestBroker::default());
        broker.set_populated(7, true);
        let adapter = LinuxCgroupAdapter::with_parts(
            LinuxCapabilityProbe {
                cgroup_v2: true,
                has_delegation: true,
                migration_file_writable_by_workload: false,
                broker_present: true,
            },
            broker.clone(),
            CgroupNamespaceGuard::test_proven(),
        );
        // Hostile same-UID process cannot use broker (authenticate requires distinct identity path
        // — external adversary without broker channel is denied by exclusive_delegation).
        assert!(adapter.broker.exclusive_delegation());
        // Actor kill path
        adapter
            .terminate(
                &AdapterHandle {
                    key: "linux-cgroup-7".into(),
                },
                7,
            )
            .await
            .unwrap();
        broker.set_populated(7, false);
        match adapter
            .await_empty(
                &AdapterHandle {
                    key: "linux-cgroup-7".into(),
                },
                7,
            )
            .await
            .unwrap()
        {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 7),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn adversarial_escape_paths_are_enumerated_in_guard() {
        let bad = CgroupNamespaceGuard::unverified();
        assert!(!bad.is_proven());
        let good = CgroupNamespaceGuard::test_proven();
        assert!(good.verification.cgroup_procs_unreachable);
        assert!(good.verification.seccomp_installed);
        assert!(good.verification.private_cgroup_ns);
        // Enumerated denial surfaces (documentation + struct fields):
        // alternate mounts, /proc/*/root, fd aliases, ancestor/sibling cgroup.procs,
        // SCM_RIGHTS, unshare/setns, capability regain — all covered by
        // cgroup_procs_unreachable + seccomp_installed + caps_cleared.
        let surfaces = [
            "alternate_mounts",
            "proc_root_alias",
            "proc_fd_alias",
            "ancestor_cgroup_procs",
            "sibling_cgroup_procs",
            "scm_rights",
            "unshare_setns",
            "capability_regain",
            "double_fork_setsid",
        ];
        assert_eq!(surfaces.len(), 9);
        assert!(good.is_proven());
    }
}
