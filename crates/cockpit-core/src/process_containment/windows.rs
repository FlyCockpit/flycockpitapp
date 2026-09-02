//! Windows Job Object adapter.
//!
//! Proven uses a fresh non-breakaway Job Object per generation with
//! JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. The adapter allocates that object and
//! never runs `req.program`. Callers spawn into the returned
//! [`ProcessTreeGuard`] with `CREATE_SUSPENDED`, prove membership with
//! `AssignProcessToJobObject` / `IsProcessInJob`, then `ResumeThread` only
//! after drop-safety / write-scope release is armed. Kernel accounting
//! (`QueryInformationJobObject` ActiveProcesses) is the empty oracle.
//!
//! Nested-job hosts (`IsProcessInJob(GetCurrentProcess(), NULL)`) force
//! Unsupported: assignment may succeed via nesting while an outer job still
//! owns the process. The host `ProcessTreeGuard` owns the syscalls. This
//! adapter never fabricates Proven from an in-memory log.
//!
//! Direct `windows-sys = "=0.61.2"` feature request lives on this crate's
//! target-specific dependency (not via cockpit-config).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cockpit_host::process::ProcessTreeGuard;

use super::adapter::{
    AdapterHandle, AllocatedContainment, ContainerExecRequest, ContainmentAdapter,
    NativeSpawnRequest,
};
use super::types::{
    ContainmentError, ContainmentGuarantee, EmptyOutcome, PlatformKind, SafeContainmentMetadata,
    SafeLocator,
};

/// Off-Windows hosts cannot create Job Objects.
pub const WINDOWS_JOB_UNAVAILABLE_ON_HOST: &str = "windows_job_objects_unavailable_on_this_host";

/// Nested-job or breakaway conditions force Unsupported.
///
/// `nested_job_restricted` is set by [`WindowsJobAdapter::production`] from a
/// live `IsProcessInJob(GetCurrentProcess(), NULL)` probe. Tests may set it
/// directly. `breakaway_ok` / `completion_port_ok` remain test knobs:
/// production never sets `JOB_OBJECT_LIMIT_BREAKAWAY_OK`, and the empty
/// oracle is `QueryInformationJobObject`, not a completion port.
#[derive(Debug, Clone)]
pub struct WindowsJobConfig {
    pub nested_job_restricted: bool,
    pub breakaway_ok: bool,
    pub completion_port_ok: bool,
}

impl Default for WindowsJobConfig {
    fn default() -> Self {
        Self {
            nested_job_restricted: false,
            breakaway_ok: true,
            completion_port_ok: true,
        }
    }
}

/// Live generation bound to a real Job Object (Windows) or absent (tests).
struct JobLive {
    generation: u64,
    #[cfg(windows)]
    guard: Arc<ProcessTreeGuard>,
}

/// Windows Job Object containment adapter.
///
/// On non-Windows hosts this still compiles as a logic/test adapter and
/// reports Unsupported; real CreateJobObjectW symbols are only linked on
/// Windows via windows-sys / `ProcessTreeGuard`.
pub struct WindowsJobAdapter {
    config: WindowsJobConfig,
    jobs: Mutex<std::collections::HashMap<String, JobLive>>,
    #[cfg(test)]
    order_log: Mutex<Vec<&'static str>>,
}

impl Default for WindowsJobAdapter {
    fn default() -> Self {
        Self::new(WindowsJobConfig::default())
    }
}

impl WindowsJobAdapter {
    pub fn new(config: WindowsJobConfig) -> Self {
        Self {
            config,
            jobs: Mutex::new(std::collections::HashMap::new()),
            #[cfg(test)]
            order_log: Mutex::new(Vec::new()),
        }
    }

    pub fn production() -> Self {
        #[cfg(windows)]
        {
            let nested = ProcessTreeGuard::current_process_is_in_job().unwrap_or(true);
            Self::new(WindowsJobConfig {
                nested_job_restricted: nested,
                breakaway_ok: true,
                completion_port_ok: true,
            })
        }
        #[cfg(not(windows))]
        {
            Self::new(WindowsJobConfig::default())
        }
    }

    fn reason_if_unsupported(&self) -> Option<&'static str> {
        if self.config.nested_job_restricted {
            return Some("nested_job_restricted");
        }
        if !self.config.breakaway_ok {
            return Some("breakaway_flags_present");
        }
        if !self.config.completion_port_ok {
            return Some("completion_port_unavailable");
        }
        #[cfg(not(windows))]
        {
            return Some(WINDOWS_JOB_UNAVAILABLE_ON_HOST);
        }
        #[cfg(windows)]
        None
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
        let removed = self.jobs.lock().unwrap().remove(key);
        #[cfg(windows)]
        if let Some(job) = removed {
            let _ = job.guard.close_job();
        }
        #[cfg(not(windows))]
        {
            let _ = removed;
        }
    }

    #[cfg(windows)]
    fn allocate_job(
        &self,
        req: &NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        let guard = Arc::new(
            ProcessTreeGuard::allocate()
                .map_err(|e| Self::unavailable(format!("job_object_prepare_failed: {e}")))?,
        );
        self.push_order("CreateJobObjectW");
        self.push_order("SetInformationJobObject_KILL_ON_CLOSE");

        // Fail closed if the job handle is already gone; do not claim Proven.
        if !guard.job_is_open() {
            return Err(Self::unavailable("job_object_closed_before_membership"));
        }

        let key = format!("job-{}-{}", req.containment_id, req.generation);
        self.jobs.lock().unwrap().insert(
            key.clone(),
            JobLive {
                generation: req.generation,
                guard,
            },
        );
        Ok(AllocatedContainment {
            locator: SafeLocator {
                locator_key: Some(key.clone()),
                nonce: Some(format!("wj{}", req.generation)),
                ..Default::default()
            },
            guarantee: ContainmentGuarantee::Proven,
            handle: AdapterHandle { key },
        })
    }
}

#[async_trait]
impl ContainmentAdapter for WindowsJobAdapter {
    fn platform_kind(&self) -> PlatformKind {
        PlatformKind::WindowsJob
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
            platform_kind: PlatformKind::WindowsJob,
            guarantee: self.guarantee(),
            capability_reason: self.reason_if_unsupported().map(|s| s.into()),
            adapter_name: "windows_job_object".into(),
            management_boundary: Some("job_object_kill_on_close".into()),
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
        #[cfg(windows)]
        {
            self.allocate_job(&req)
        }
        #[cfg(not(windows))]
        {
            let _ = req;
            Err(Self::unavailable(WINDOWS_JOB_UNAVAILABLE_ON_HOST))
        }
    }

    async fn create_container_and_exec(
        &self,
        _req: ContainerExecRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        Err(Self::unavailable("windows_adapter_is_native_only"))
    }

    async fn terminate(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<(), ContainmentError> {
        let mut jobs = self.jobs.lock().unwrap();
        if let Some(job) = jobs.get_mut(&handle.key) {
            if job.generation != generation {
                return Err(ContainmentError::GenerationMismatch {
                    expected: job.generation,
                    got: generation,
                });
            }
            #[cfg(windows)]
            {
                job.guard
                    .terminate()
                    .map_err(|e| Self::unavailable(format!("job_object_terminate_failed: {e}")))?;
            }
            self.push_order("TerminateJobObject");
        }
        Ok(())
    }

    async fn await_empty(
        &self,
        handle: &AdapterHandle,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        let outcome = {
            let jobs = self.jobs.lock().unwrap();
            match jobs.get(&handle.key) {
                Some(job) if job.generation == generation => {
                    #[cfg(windows)]
                    {
                        if !job.guard.job_is_open() {
                            self.push_order("ActiveProcessZero");
                            EmptyOutcome::ProvenEmpty { generation }
                        } else {
                            match job.guard.active_process_count() {
                                Ok(0) => {
                                    self.push_order("ActiveProcessZero");
                                    EmptyOutcome::ProvenEmpty { generation }
                                }
                                Ok(_) => EmptyOutcome::Uncertain {
                                    generation,
                                    reason: "active_processes_nonzero".into(),
                                },
                                Err(e) => EmptyOutcome::Uncertain {
                                    generation,
                                    reason: format!("job_object_query_failed: {e}"),
                                },
                            }
                        }
                    }
                    #[cfg(not(windows))]
                    {
                        let _ = job;
                        EmptyOutcome::Unsupported {
                            reason: WINDOWS_JOB_UNAVAILABLE_ON_HOST.into(),
                        }
                    }
                }
                Some(_) => EmptyOutcome::Uncertain {
                    generation,
                    reason: "job_generation_mismatch".into(),
                },
                // Daemon death: kill-on-close closed handles; absent named job.
                None => EmptyOutcome::ProvenEmpty { generation },
            }
        };
        if matches!(outcome, EmptyOutcome::ProvenEmpty { .. }) {
            self.reclaim(&handle.key);
        }
        Ok(outcome)
    }

    async fn recover(
        &self,
        locator: &SafeLocator,
        generation: u64,
    ) -> Result<EmptyOutcome, ContainmentError> {
        // After daemon death, previously Active is Uncertain until named job absent.
        let key = locator.locator_key.clone().unwrap_or_default();
        let jobs = self.jobs.lock().unwrap();
        if let Some(job) = jobs.get(&key) {
            #[cfg(windows)]
            {
                if job.guard.job_is_open() {
                    match job.guard.active_process_count() {
                        Ok(0) => {}
                        Ok(_) => {
                            return Ok(EmptyOutcome::Uncertain {
                                generation,
                                reason: "job_still_active_after_restart".into(),
                            });
                        }
                        Err(e) => {
                            return Ok(EmptyOutcome::Uncertain {
                                generation,
                                reason: format!("job_object_query_failed: {e}"),
                            });
                        }
                    }
                }
            }
            #[cfg(not(windows))]
            {
                let _ = job;
            }
        }
        // No reusable locator accepted across generations.
        Ok(EmptyOutcome::ProvenEmpty { generation })
    }

    fn process_tree_guard(&self, handle: &AdapterHandle) -> Option<Arc<ProcessTreeGuard>> {
        #[cfg(windows)]
        {
            let jobs = self.jobs.lock().ok()?;
            jobs.get(&handle.key).map(|job| Arc::clone(&job.guard))
        }
        #[cfg(not(windows))]
        {
            let _ = handle;
            None
        }
    }
}

impl WindowsJobAdapter {
    /// Close every process/thread/job handle on all branches.
    pub fn close_handles(&self, handle: &AdapterHandle) {
        self.reclaim(&handle.key);
        self.push_order("CloseHandle_all");
    }

    #[cfg(test)]
    pub fn order(&self) -> Vec<&'static str> {
        self.order_log.lock().unwrap().clone()
    }

    #[cfg(test)]
    fn live_job_count(&self) -> usize {
        self.jobs.lock().unwrap().len()
    }
}

/// Compile-time / inventory symbols used only on Windows.
#[cfg(windows)]
pub mod job_symbols {
    #![allow(unused_imports)]
    // Resolve Job Object symbols from this crate's direct windows-sys request.
    pub use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    pub use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
        JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
    };
    pub use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessW, GetCurrentProcess, PROCESS_INFORMATION, ResumeThread,
        STARTUPINFOW,
    };

    #[cfg(test)]
    pub fn inventory_symbol_names() -> &'static [&'static str] {
        &[
            "CreateJobObjectW",
            "SetInformationJobObject",
            "AssignProcessToJobObject",
            "IsProcessInJob",
            "QueryInformationJobObject",
            "TerminateJobObject",
            "JobObjectAssociateCompletionPortInformation",
            "CreateProcessW",
            "ResumeThread",
            "CloseHandle",
            "GetCurrentProcess",
        ]
    }
}

#[cfg(test)]
mod windows_job_spawn_before_resume {
    use super::*;

    fn sleeper_request(generation: u64) -> NativeSpawnRequest {
        NativeSpawnRequest {
            containment_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            generation,
            operation_id: "op".into(),
            program: "cmd.exe".into(),
            args: vec![
                "/C".into(),
                "ping".into(),
                "-n".into(),
                "20".into(),
                "127.0.0.1".into(),
            ],
            cwd: ".".into(),
            require_proven: true,
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn create_and_spawn_allocates_job_without_running_user_code() {
        use std::process::Stdio;

        let adapter = WindowsJobAdapter::new(WindowsJobConfig::default());
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Proven);
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        assert_eq!(allocated.guarantee, ContainmentGuarantee::Proven);
        let order = adapter.order();
        assert!(order.contains(&"CreateJobObjectW"));
        assert!(order.contains(&"SetInformationJobObject_KILL_ON_CLOSE"));
        assert!(
            !order.contains(&"ResumeThread"),
            "create_and_spawn must not resume user instructions"
        );
        assert!(
            !order.contains(&"CreateProcessW_CREATE_SUSPENDED"),
            "create_and_spawn must not spawn req.program"
        );

        let tree = adapter
            .process_tree_guard(&allocated.handle)
            .expect("allocated job");
        assert_eq!(
            tree.active_process_count()
                .expect("QueryInformationJobObject"),
            0,
            "lease creation must not place a process"
        );

        let mut command = tokio::process::Command::new("cmd.exe");
        command
            .args(["/C", "ping", "-n", "20", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        tree.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("CreateProcessW CREATE_SUSPENDED");
        tree.assign(&child).expect("AssignProcessToJobObject");
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::Uncertain { reason, .. } => {
                assert_eq!(reason, "active_processes_nonzero");
            }
            o => panic!("live job must not fabricate empty: {o:?}"),
        }
        tree.resume(&child).expect("ResumeThread");

        adapter.terminate(&allocated.handle, 1).await.unwrap();
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 1),
            o => panic!("{o:?}"),
        }
        assert_eq!(
            adapter.live_job_count(),
            0,
            "ProvenEmpty must reclaim the job handle"
        );
        let _ = child.try_wait();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn create_and_spawn_ignores_missing_user_program() {
        let adapter = WindowsJobAdapter::new(WindowsJobConfig::default());
        let allocated = adapter
            .create_and_spawn(NativeSpawnRequest {
                containment_id: uuid::Uuid::new_v4(),
                session_id: uuid::Uuid::new_v4(),
                generation: 1,
                operation_id: "op".into(),
                program: "cockpit_missing_job_object_probe.exe".into(),
                args: vec![],
                cwd: ".".into(),
                require_proven: true,
            })
            .await
            .expect("missing program must not be spawned at lease creation");
        assert_eq!(allocated.guarantee, ContainmentGuarantee::Proven);
        adapter.close_handles(&allocated.handle);
        assert!(adapter.order().contains(&"CloseHandle_all"));
        assert_eq!(adapter.live_job_count(), 0);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn production_nested_job_probe_matches_host() {
        let in_job = ProcessTreeGuard::current_process_is_in_job().expect("IsProcessInJob");
        let adapter = WindowsJobAdapter::production();
        if in_job {
            assert_eq!(adapter.guarantee(), ContainmentGuarantee::Unsupported);
            let err = adapter
                .create_and_spawn(sleeper_request(1))
                .await
                .unwrap_err();
            match err {
                ContainmentError::DescendantContainmentUnavailable { reason } => {
                    assert_eq!(reason, "nested_job_restricted");
                }
                o => panic!("{o:?}"),
            }
        } else {
            assert_eq!(adapter.guarantee(), ContainmentGuarantee::Proven);
            let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
            assert_eq!(allocated.guarantee, ContainmentGuarantee::Proven);
            adapter.close_handles(&allocated.handle);
        }
    }

    #[cfg(not(windows))]
    #[tokio::test]
    async fn production_adapter_is_unsupported_off_windows() {
        let adapter = WindowsJobAdapter::production();
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Unsupported);
        assert_eq!(
            adapter.safe_metadata().capability_reason.as_deref(),
            Some(WINDOWS_JOB_UNAVAILABLE_ON_HOST)
        );
        let err = adapter
            .create_and_spawn(sleeper_request(1))
            .await
            .unwrap_err();
        match err {
            ContainmentError::DescendantContainmentUnavailable { reason } => {
                assert_eq!(reason, WINDOWS_JOB_UNAVAILABLE_ON_HOST);
            }
            o => panic!("{o:?}"),
        }
    }

    #[tokio::test]
    async fn nested_job_failure_is_unsupported() {
        let adapter = WindowsJobAdapter::new(WindowsJobConfig {
            nested_job_restricted: true,
            ..Default::default()
        });
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Unsupported);
        let err = adapter
            .create_and_spawn(NativeSpawnRequest {
                containment_id: uuid::Uuid::new_v4(),
                session_id: uuid::Uuid::new_v4(),
                generation: 1,
                operation_id: "op".into(),
                program: "cmd.exe".into(),
                args: vec![],
                cwd: ".".into(),
                require_proven: true,
            })
            .await
            .unwrap_err();
        match err {
            ContainmentError::DescendantContainmentUnavailable { reason } => {
                assert_eq!(reason, "nested_job_restricted");
            }
            o => panic!("{o:?}"),
        }
    }

    #[tokio::test]
    async fn daemon_death_kill_on_close_absent_job() {
        let adapter = WindowsJobAdapter::default();
        // No live job handle after daemon death → ProvenEmpty when absent.
        match adapter
            .recover(
                &SafeLocator {
                    locator_key: Some("job-gone".into()),
                    ..Default::default()
                },
                3,
            )
            .await
            .unwrap()
        {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 3),
            o => panic!("{o:?}"),
        }
    }
}
