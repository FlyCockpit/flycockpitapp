//! Unix process-group adapter backed by [`ProcessTreeGuard`].
//!
//! Shared by the Linux and macOS native adapters. Allocation creates an empty
//! guard; callers spawn into it with `process_group(0)`, prove membership with
//! `getpgid` / `kill(-pgid, 0)`, then terminate the group. The empty oracle is
//! that same existence probe — never an in-memory populated flag. Off-host
//! builds return Unsupported and never fabricate Proven.
//!
//! `ContainmentGuarantee::Proven` here means the kernel process-group
//! existence probe is the empty oracle. Process groups are opt-out
//! (`setpgid` / `setsid`); that is weaker than a Windows Job Object under
//! the same `Proven` label and is the mandated [`ProcessTreeGuard`] ceiling,
//! not a fabricated heuristic oracle.
//!
//! A pgid is a bare integer identity. Signal authority requires a
//! parent-owned leader pin (`waitid` WNOWAIT plus the start identity
//! captured at assign). `terminate` is one-shot after Ok/ESRCH; a failed
//! signal may retry only while that pin holds. Losing the pin without a
//! successful SIGKILL forgets the pgid (Unattributable). `ProvenEmpty`
//! reclaims the live guard. `Uncertain` after a failed bind or pin-loss
//! forgets the pgid so a later retry cannot SIGKILL a recycled process
//! group. `Uncertain` after a delivered SIGKILL while the group is still
//! populated keeps the live guard: signal authority is already consumed
//! (one-shot), and the empty oracle is one-sided safe (a recycled pgid
//! can only yield false-Populated, never false-Empty). Adapter memory is
//! the live map of in-flight leases only.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cockpit_host::process::ProcessTreeGuard;
#[cfg(unix)]
use cockpit_host::process::{GroupPopulation, PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE};

use super::adapter::{
    AdapterHandle, AllocatedContainment, ContainerExecRequest, ContainmentAdapter,
    NativeSpawnRequest,
};
#[cfg(unix)]
use super::types::PROCESS_GROUP_STILL_POPULATED;
use super::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, PlatformKind, SafeContainmentMetadata,
    SafeLocator,
};

/// Kernel membership is unproven while no process-group leader has been assigned.
pub const PROCESS_GROUP_EMPTY_MEMBERSHIP_UNPROVEN: &str = "process_group_empty_membership_unproven";

/// Which native Unix host this adapter represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnixHost {
    Linux,
    Macos,
}

impl UnixHost {
    fn is_native(self) -> bool {
        match self {
            Self::Linux => cfg!(target_os = "linux"),
            Self::Macos => cfg!(target_os = "macos"),
        }
    }

    fn platform_kind(self) -> PlatformKind {
        match self {
            Self::Linux => PlatformKind::LinuxProcessGroup,
            Self::Macos => PlatformKind::MacosProcessGroup,
        }
    }

    fn adapter_name(self) -> &'static str {
        match self {
            Self::Linux => "linux_process_tree_guard",
            Self::Macos => "macos_process_tree_guard",
        }
    }

    fn unavailable_reason(self) -> &'static str {
        match self {
            Self::Linux => LINUX_PROCESS_TREE_UNAVAILABLE_ON_HOST,
            Self::Macos => MACOS_PROCESS_TREE_UNAVAILABLE_ON_HOST,
        }
    }
}

/// Off-Linux hosts cannot create a Linux process-tree generation.
pub const LINUX_PROCESS_TREE_UNAVAILABLE_ON_HOST: &str =
    "linux_process_tree_unavailable_on_this_host";

/// Off-macOS hosts cannot create a macOS process-tree generation.
pub const MACOS_PROCESS_TREE_UNAVAILABLE_ON_HOST: &str =
    "macos_process_tree_unavailable_on_this_host";

struct UnixLive {
    generation: u64,
    #[cfg(unix)]
    guard: Arc<ProcessTreeGuard>,
}

pub(super) struct UnixProcessTreeAdapter {
    host: UnixHost,
    live: Mutex<HashMap<String, UnixLive>>,
    #[cfg(test)]
    order_log: Mutex<Vec<&'static str>>,
}

impl UnixProcessTreeAdapter {
    pub(super) fn new(host: UnixHost) -> Self {
        Self {
            host,
            live: Mutex::new(HashMap::new()),
            #[cfg(test)]
            order_log: Mutex::new(Vec::new()),
        }
    }

    fn reason_if_unsupported(&self) -> Option<&'static str> {
        if self.host.is_native() {
            #[cfg(unix)]
            {
                return None;
            }
            #[cfg(not(unix))]
            {
                return Some(self.host.unavailable_reason());
            }
        }
        Some(self.host.unavailable_reason())
    }

    fn push_order(&self, step: &'static str) {
        #[cfg(test)]
        self.order_log.lock().unwrap().push(step);
        #[cfg(not(test))]
        let _ = step;
    }

    fn unavailable(reason: impl Into<String>) -> ContainmentError {
        ContainmentError::DescendantContainmentUnavailable {
            reason: reason.into(),
        }
    }

    fn reclaim(&self, key: &str) {
        let removed = self.live.lock().unwrap().remove(key);
        #[cfg(unix)]
        if let Some(job) = removed {
            job.guard.release_group();
        }
        #[cfg(not(unix))]
        {
            let _ = removed;
        }
    }

    #[cfg(unix)]
    fn drop_signal_authority_and_reclaim(&self, key: &str) {
        let removed = self.live.lock().unwrap().remove(key);
        if let Some(job) = removed {
            job.guard.release_signal_authority();
            job.guard.release_group();
        }
    }

    #[cfg(unix)]
    fn allocate_group(
        &self,
        req: &NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        let guard = Arc::new(
            ProcessTreeGuard::allocate()
                .map_err(|e| Self::unavailable(format!("process_group_prepare_failed: {e}")))?,
        );
        self.push_order("allocate_process_tree_guard");
        if guard.group_is_bound() {
            return Err(Self::unavailable(
                "process_group_bound_before_membership".to_string(),
            ));
        }
        let key = format!("pg-{}-{}", req.containment_id, req.generation);
        self.live.lock().unwrap().insert(
            key.clone(),
            UnixLive {
                generation: req.generation,
                guard,
            },
        );
        Ok(AllocatedContainment {
            locator: SafeLocator {
                locator_key: Some(key.clone()),
                nonce: Some(format!("pg{}", req.generation)),
                ..Default::default()
            },
            guarantee: ContainmentGuarantee::Proven,
            handle: AdapterHandle { key },
        })
    }

    #[cfg(test)]
    pub(super) fn close_handles(&self, handle: &AdapterHandle) {
        self.reclaim(&handle.key);
        self.push_order("release_group");
    }

    #[cfg(test)]
    pub(super) fn order(&self) -> Vec<&'static str> {
        self.order_log.lock().unwrap().clone()
    }

    #[cfg(all(test, unix))]
    pub(super) fn live_group_count(&self) -> usize {
        self.live.lock().unwrap().len()
    }
}

#[async_trait]
impl ContainmentAdapter for UnixProcessTreeAdapter {
    fn platform_kind(&self) -> PlatformKind {
        self.host.platform_kind()
    }

    fn guarantee(&self) -> ContainmentGuarantee {
        if self.reason_if_unsupported().is_some() {
            ContainmentGuarantee::Unsupported
        } else {
            ContainmentGuarantee::Proven
        }
    }

    fn safe_metadata(&self) -> SafeContainmentMetadata {
        SafeContainmentMetadata {
            platform_kind: self.host.platform_kind(),
            guarantee: self.guarantee(),
            capability_reason: self.reason_if_unsupported().map(|s| s.into()),
            adapter_name: self.host.adapter_name().into(),
            management_boundary: Some("unix_process_group".into()),
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
            return Err(Self::unavailable(reason));
        }
        #[cfg(unix)]
        {
            self.allocate_group(&req)
        }
        #[cfg(not(unix))]
        {
            let _ = req;
            Err(Self::unavailable(self.host.unavailable_reason()))
        }
    }

    async fn prove_membership(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError> {
        #[cfg(unix)]
        {
            let result = {
                let live = self.live.lock().unwrap();
                match live.get(&handle.key) {
                    Some(job) if job.generation == generation => {
                        if job.guard.group_is_unattributable() {
                            Err(Self::unavailable(PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE))
                        } else if !job.guard.group_is_bound() {
                            Err(Self::unavailable(PROCESS_GROUP_EMPTY_MEMBERSHIP_UNPROVEN))
                        } else {
                            match job.guard.group_population() {
                                Ok(GroupPopulation::Empty) => {
                                    Err(Self::unavailable(PROCESS_GROUP_EMPTY_MEMBERSHIP_UNPROVEN))
                                }
                                Ok(GroupPopulation::Populated) => Ok(()),
                                Ok(GroupPopulation::Unattributable) => {
                                    Err(Self::unavailable(PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE))
                                }
                                Err(e) => Err(Self::unavailable(format!(
                                    "process_group_query_failed: {e}"
                                ))),
                            }
                        }
                    }
                    Some(job) => Err(ContainmentError::GenerationMismatch {
                        expected: job.generation,
                        got: generation,
                    }),
                    None => Err(Self::unavailable(
                        "process_group_missing_membership_unproven",
                    )),
                }
            };
            if result.is_ok() {
                self.push_order("getpgid_membership");
            }
            result
        }
        #[cfg(not(unix))]
        {
            let _ = (handle, generation);
            Err(Self::unavailable(self.host.unavailable_reason()))
        }
    }

    async fn create_container_and_exec(
        &self,
        _req: ContainerExecRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        Err(Self::unavailable(format!(
            "{}_adapter_is_native_only",
            self.host.adapter_name()
        )))
    }

    async fn terminate(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError> {
        let mut live = self.live.lock().unwrap();
        if let Some(job) = live.get_mut(&handle.key) {
            if job.generation != generation {
                return Err(ContainmentError::GenerationMismatch {
                    expected: job.generation,
                    got: generation,
                });
            }
            #[cfg(unix)]
            {
                job.guard.terminate().map_err(|e| {
                    Self::unavailable(format!("process_group_terminate_failed: {e}"))
                })?;
            }
            self.push_order("kill_process_group");
        }
        Ok(())
    }

    async fn await_empty(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let generation_match = {
            let live = self.live.lock().unwrap();
            live.get(&handle.key).map(|job| job.generation)
        };
        let outcome = match generation_match {
            Some(live_generation) if live_generation == generation => {
                #[cfg(unix)]
                {
                    unix_wait_group_empty(self, handle, generation).await
                }
                #[cfg(not(unix))]
                {
                    EmptyOutcome::Unsupported {
                        reason: self.host.unavailable_reason().into(),
                    }
                }
            }
            Some(_) => EmptyOutcome::Uncertain {
                generation,
                reason: "process_group_generation_mismatch".into(),
            },
            None => EmptyOutcome::Uncertain {
                generation,
                reason: "process_group_locator_not_reusable".into(),
            },
        };
        match &outcome {
            EmptyOutcome::ProvenEmpty { .. } => {
                self.reclaim(&handle.key);
                self.push_order("process_group_empty");
            }
            EmptyOutcome::Uncertain { .. } => {
                #[cfg(unix)]
                {
                    // Unattributable membership (failed bind, pin-loss without
                    // SIGKILL) cannot prove empty and must not remain a signal
                    // target: drop it. A delivered SIGKILL that has not yet
                    // drained keeps the live guard. Signal authority is already
                    // one-shot (`group_terminate_signaled`); the empty oracle
                    // is one-sided safe and is the only object that can later
                    // observe Empty once the group actually drains.
                    let drop_unattributable = {
                        let live = self.live.lock().unwrap();
                        live.get(&handle.key)
                            .map(|job| job.guard.group_is_unattributable())
                            .unwrap_or(false)
                    };
                    if drop_unattributable {
                        self.drop_signal_authority_and_reclaim(&handle.key);
                    }
                }
            }
            EmptyOutcome::Unsupported { .. } => {}
        }
        Ok(outcome)
    }

    async fn recover(
        &self,
        locator: &SafeLocator,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let key = locator.locator_key.clone().unwrap_or_default();
        #[cfg(unix)]
        {
            let population = {
                let live = self.live.lock().unwrap();
                live.get(&key).map(|job| job.guard.group_population())
            };
            match population {
                Some(Ok(GroupPopulation::Empty)) => {
                    self.reclaim(&key);
                    return Ok(EmptyOutcome::ProvenEmpty { generation });
                }
                Some(Ok(GroupPopulation::Populated)) => {
                    return Ok(EmptyOutcome::Uncertain {
                        generation,
                        reason: "process_group_still_populated_after_restart".into(),
                    });
                }
                Some(Ok(GroupPopulation::Unattributable)) => {
                    self.drop_signal_authority_and_reclaim(&key);
                    return Ok(EmptyOutcome::Uncertain {
                        generation,
                        reason: PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE.into(),
                    });
                }
                Some(Err(e)) => {
                    self.drop_signal_authority_and_reclaim(&key);
                    return Ok(EmptyOutcome::Uncertain {
                        generation,
                        reason: format!("process_group_query_failed: {e}"),
                    });
                }
                None => {}
            }
        }
        // Unix process groups are not kill-on-close kernel objects. A missing
        // locator after daemon death cannot prove descendants are gone.
        Ok(EmptyOutcome::Uncertain {
            generation,
            reason: "process_group_locator_not_reusable".into(),
        })
    }

    fn process_tree_guard(&self, handle: &AdapterHandle) -> Option<Arc<ProcessTreeGuard>> {
        #[cfg(unix)]
        {
            let live = self.live.lock().ok()?;
            live.get(&handle.key).map(|job| Arc::clone(&job.guard))
        }
        #[cfg(not(unix))]
        {
            let _ = handle;
            None
        }
    }
}

#[cfg(unix)]
async fn unix_wait_group_empty(
    adapter: &UnixProcessTreeAdapter,
    handle: &AdapterHandle,
    generation: u64,
) -> EmptyOutcome {
    // Brief probe so a just-SIGKILL'd group that has already drained is
    // observed Empty on this call. Still-populated groups stay Uncertain
    // (`PROCESS_GROUP_STILL_POPULATED`); after SIGKILL the live oracle is
    // kept so a later probe can settle. Callers that need ProvenEmpty
    // re-probe (`await_empty_until`, `await_all_empty`) until Empty or
    // their deadline.
    for _ in 0..20 {
        let population = {
            let live = adapter.live.lock().unwrap();
            match live.get(&handle.key) {
                Some(job) if job.generation == generation => job.guard.group_population(),
                _ => {
                    return EmptyOutcome::Uncertain {
                        generation,
                        reason: "process_group_missing".into(),
                    };
                }
            }
        };
        match population {
            Ok(GroupPopulation::Empty) => {
                return EmptyOutcome::ProvenEmpty { generation };
            }
            Ok(GroupPopulation::Populated) => {}
            Ok(GroupPopulation::Unattributable) => {
                return EmptyOutcome::Uncertain {
                    generation,
                    reason: PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE.into(),
                };
            }
            Err(e) => {
                return EmptyOutcome::Uncertain {
                    generation,
                    reason: format!("process_group_query_failed: {e}"),
                };
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    EmptyOutcome::Uncertain {
        generation,
        reason: PROCESS_GROUP_STILL_POPULATED.into(),
    }
}

macro_rules! impl_unix_host_adapter {
    ($ty:ty) => {
        #[async_trait]
        impl ContainmentAdapter for $ty {
            fn platform_kind(&self) -> PlatformKind {
                self.0.platform_kind()
            }
            fn guarantee(&self) -> ContainmentGuarantee {
                self.0.guarantee()
            }
            fn safe_metadata(&self) -> SafeContainmentMetadata {
                self.0.safe_metadata()
            }
            async fn probe(&self) -> Result<SafeContainmentMetadata, ContainmentError> {
                self.0.probe().await
            }
            async fn create_and_spawn(
                &self,
                req: NativeSpawnRequest,
            ) -> Result<AllocatedContainment, ContainmentError> {
                self.0.create_and_spawn(req).await
            }
            async fn prove_membership(
                &self,
                handle: &AdapterHandle,
                generation: u64,
            ) -> Result<(), ContainmentError> {
                self.0.prove_membership(handle, generation).await
            }
            async fn create_container_and_exec(
                &self,
                req: ContainerExecRequest,
            ) -> Result<AllocatedContainment, ContainmentError> {
                self.0.create_container_and_exec(req).await
            }
            async fn terminate(
                &self,
                handle: &AdapterHandle,
                generation: u64,
            ) -> Result<(), ContainmentError> {
                self.0.terminate(handle, generation).await
            }
            async fn await_empty(
                &self,
                handle: &AdapterHandle,
                generation: u64,
            ) -> Result<EmptyOutcome, ContainmentError> {
                self.0.await_empty(handle, generation).await
            }
            async fn recover(
                &self,
                locator: &SafeLocator,
                generation: u64,
            ) -> Result<EmptyOutcome, ContainmentError> {
                self.0.recover(locator, generation).await
            }
            fn process_tree_guard(&self, handle: &AdapterHandle) -> Option<Arc<ProcessTreeGuard>> {
                self.0.process_tree_guard(handle)
            }
        }
    };
}

pub(super) use impl_unix_host_adapter;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod unix_settlement_invariants {
    use super::*;
    use cockpit_host::process::PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE;
    use std::process::Stdio;

    fn native_adapter() -> UnixProcessTreeAdapter {
        #[cfg(target_os = "linux")]
        {
            UnixProcessTreeAdapter::new(UnixHost::Linux)
        }
        #[cfg(target_os = "macos")]
        {
            UnixProcessTreeAdapter::new(UnixHost::Macos)
        }
    }

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

    #[tokio::test]
    async fn never_spawned_lease_is_proven_empty_and_reclaimed() {
        let adapter = native_adapter();
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 1),
            o => panic!("unbound lease must be empty: {o:?}"),
        }
        assert_eq!(adapter.live_group_count(), 0);
    }

    #[tokio::test]
    async fn assign_failure_settles_uncertain_not_empty() {
        let adapter = native_adapter();
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        let tree = adapter
            .process_tree_guard(&allocated.handle)
            .expect("allocated guard");
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().expect("spawn outside the lease group");
        assert!(
            tree.assign(&child).is_err(),
            "child that is not a group leader must fail bind"
        );
        assert!(tree.group_is_unattributable());
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::Uncertain { generation, reason } => {
                assert_eq!(generation, 1);
                assert_eq!(reason, PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE);
            }
            o => panic!("spawned-unbound must not fabricate ProvenEmpty: {o:?}"),
        }
        assert_eq!(
            adapter.live_group_count(),
            0,
            "Uncertain bind-failure must drop signal authority"
        );
        let _ = child.start_kill();
        let _ = child.wait().await;
    }

    #[tokio::test]
    async fn second_assign_cannot_launder_unattributable_into_empty() {
        let adapter = native_adapter();
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        let tree = adapter
            .process_tree_guard(&allocated.handle)
            .expect("allocated guard");
        let mut outsider = tokio::process::Command::new("/bin/sh");
        outsider
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut first = outsider.spawn().expect("spawn outside the lease group");
        assert!(tree.assign(&first).is_err());
        assert!(tree.group_is_unattributable());

        let mut leader = tokio::process::Command::new("/bin/sh");
        leader
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        tree.apply_spawn_flags(&mut leader);
        let mut second = leader.spawn().expect("spawn group leader");
        assert!(
            tree.assign(&second).is_err(),
            "unattributable membership is terminal for assign"
        );
        assert!(tree.group_is_unattributable());
        adapter
            .terminate(&allocated.handle, 1)
            .await
            .expect("unattributable terminate is a no-op");
        let _ = first.start_kill();
        let _ = first.wait().await;
        let _ = second.start_kill();
        let _ = second.wait().await;
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::Uncertain { generation, reason } => {
                assert_eq!(generation, 1);
                assert_eq!(reason, PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE);
            }
            o => panic!("second assign must not fabricate ProvenEmpty: {o:?}"),
        }
    }

    #[tokio::test]
    async fn reap_without_signal_settles_uncertain_and_drops_authority() {
        let adapter = native_adapter();
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        let tree = adapter
            .process_tree_guard(&allocated.handle)
            .expect("allocated guard");
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        tree.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn into the lease group");
        tree.assign(&child).expect("bind");
        let _ = child.start_kill();
        let _ = child.wait().await;
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::Uncertain { generation, reason } => {
                assert_eq!(generation, 1);
                assert_eq!(reason, PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE);
            }
            o => panic!("pin-loss without SIGKILL must not probe a recycled pgid: {o:?}"),
        }
        assert_eq!(
            adapter.live_group_count(),
            0,
            "pin-loss without signal must drop signal authority"
        );
    }

    #[tokio::test]
    async fn successful_signal_then_reap_can_still_prove_empty() {
        let adapter = native_adapter();
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        let tree = adapter
            .process_tree_guard(&allocated.handle)
            .expect("allocated guard");
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        tree.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn into the lease group");
        tree.assign(&child).expect("bind");
        adapter
            .terminate(&allocated.handle, 1)
            .await
            .expect("SIGKILL");
        let _ = child.wait().await;
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 1),
            o => panic!("successful SIGKILL must still settle empty after reap: {o:?}"),
        }
        assert_eq!(adapter.live_group_count(), 0);
    }

    #[tokio::test]
    async fn successful_signal_slow_drain_keeps_empty_oracle() {
        let adapter = native_adapter();
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        let tree = adapter
            .process_tree_guard(&allocated.handle)
            .expect("allocated guard");
        let mut command = tokio::process::Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        tree.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn into the lease group");
        tree.assign(&child).expect("bind");
        adapter
            .terminate(&allocated.handle, 1)
            .await
            .expect("SIGKILL");
        // Do not reap: the zombie leader keeps the group resolvable, so the
        // ~100ms probe cannot prove Empty. Signal authority is spent; the
        // empty oracle must survive so a later drain can settle.
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::Uncertain { generation, reason } => {
                assert_eq!(generation, 1);
                assert_eq!(reason, PROCESS_GROUP_STILL_POPULATED);
            }
            o => panic!("unreaped SIGKILL'd leader must not fabricate Empty: {o:?}"),
        }
        assert_eq!(
            adapter.live_group_count(),
            1,
            "SIGKILL Uncertain must keep the empty oracle"
        );
        match adapter
            .recover(&allocated.locator, 1)
            .await
            .expect("recover")
        {
            EmptyOutcome::Uncertain { reason, .. } => {
                assert_ne!(
                    reason, "process_group_locator_not_reusable",
                    "kept oracle must remain recoverable"
                );
            }
            EmptyOutcome::ProvenEmpty { .. } => {}
            o => panic!("recover must still see the live group: {o:?}"),
        }
        let _ = child.wait().await;
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 1),
            o => panic!("kept oracle must prove Empty once the group drains: {o:?}"),
        }
        assert_eq!(adapter.live_group_count(), 0);
    }

    #[tokio::test]
    async fn completed_leases_do_not_accumulate_adapter_state() {
        let adapter = native_adapter();
        for generation in 1..=8 {
            let allocated = adapter
                .create_and_spawn(sleeper_request(generation))
                .await
                .unwrap();
            match adapter
                .await_empty(&allocated.handle, generation)
                .await
                .unwrap()
            {
                EmptyOutcome::ProvenEmpty { .. } => {}
                o => panic!("{o:?}"),
            }
        }
        assert_eq!(
            adapter.live_group_count(),
            0,
            "adapter memory must be bounded by live leases"
        );
    }

    #[test]
    fn platform_kind_names_the_process_group() {
        let adapter = native_adapter();
        let meta = adapter.safe_metadata();
        assert_eq!(meta.guarantee, ContainmentGuarantee::Proven);
        assert_eq!(
            meta.management_boundary.as_deref(),
            Some("unix_process_group")
        );
        #[cfg(target_os = "linux")]
        assert_eq!(meta.platform_kind, PlatformKind::LinuxProcessGroup);
        #[cfg(target_os = "macos")]
        assert_eq!(meta.platform_kind, PlatformKind::MacosProcessGroup);
    }
}
