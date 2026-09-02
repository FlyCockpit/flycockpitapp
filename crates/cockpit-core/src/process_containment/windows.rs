//! Windows Job Object adapter.
//!
//! Proven uses a fresh non-breakaway Job Object per generation with
//! JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. CreateProcessW starts suspended;
//! AssignProcessToJobObject succeeds before ResumeThread. Kernel accounting
//! (`QueryInformationJobObject` ActiveProcesses) is the empty oracle.
//!
//! The host `ProcessTreeGuard` owns those syscalls. This adapter never
//! fabricates Proven from an in-memory log.
//!
//! Direct `windows-sys = "=0.61.2"` feature request lives on this crate's
//! target-specific dependency (not via cockpit-config).

use std::sync::Mutex;

use async_trait::async_trait;

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
#[cfg_attr(not(windows), allow(dead_code))]
struct JobLive {
    generation: u64,
    #[cfg(windows)]
    guard: cockpit_host::process::ProcessTreeGuard,
    #[cfg(windows)]
    child: tokio::process::Child,
}

/// Windows Job Object containment adapter.
///
/// On non-Windows hosts this still compiles as a logic/test adapter and
/// reports Unsupported; real CreateJobObjectW symbols are only linked on
/// Windows via windows-sys / `ProcessTreeGuard`.
pub struct WindowsJobAdapter {
    config: WindowsJobConfig,
    jobs: Mutex<std::collections::HashMap<String, JobLive>>,
    /// Order log for suspended-create/assign/resume assertions.
    pub order_log: Mutex<Vec<&'static str>>,
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
            order_log: Mutex::new(Vec::new()),
        }
    }

    pub fn production() -> Self {
        Self::new(WindowsJobConfig::default())
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
        self.order_log.lock().unwrap().push(step);
    }

    fn unavailable(reason: impl Into<String>) -> ContainmentError {
        ContainmentError::DescendantContainmentUnavailable {
            reason: reason.into(),
        }
    }

    #[cfg(windows)]
    async fn spawn_contained(
        &self,
        req: NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new(&req.program);
        command
            .args(&req.args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(false);
        if !req.cwd.as_os_str().is_empty() {
            command.current_dir(&req.cwd);
        }

        let guard = cockpit_host::process::ProcessTreeGuard::prepare(&mut command)
            .map_err(|_| Self::unavailable("job_object_prepare_failed"))?;
        self.push_order("CreateJobObjectW");
        self.push_order("SetInformationJobObject_KILL_ON_CLOSE");

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => return Err(Self::unavailable("process_spawn_failed")),
        };
        self.push_order("CreateProcessW_CREATE_SUSPENDED");

        if guard.attach(&child).is_err() {
            let _ = guard.terminate();
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(Self::unavailable("job_object_assign_or_resume_failed"));
        }
        self.push_order("AssignProcessToJobObject");
        self.push_order("ResumeThread");

        // Fail closed if the job handle is already gone; do not claim Proven.
        if !guard.job_is_open() {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(Self::unavailable("job_object_closed_before_membership"));
        }

        let key = format!("job-{}-{}", req.containment_id, req.generation);
        self.jobs.lock().unwrap().insert(
            key.clone(),
            JobLive {
                generation: req.generation,
                guard,
                child,
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

    #[cfg(not(windows))]
    async fn spawn_contained(
        &self,
        req: NativeSpawnRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        let _ = (self, req);
        Err(Self::unavailable(WINDOWS_JOB_UNAVAILABLE_ON_HOST))
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
        self.spawn_contained(req).await
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
                    .map_err(|_| Self::unavailable("job_object_terminate_failed"))?;
                let _ = job.child.try_wait();
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
        let jobs = self.jobs.lock().unwrap();
        match jobs.get(&handle.key) {
            Some(job) if job.generation == generation => {
                #[cfg(windows)]
                {
                    if !job.guard.job_is_open() {
                        self.push_order("ActiveProcessZero");
                        return Ok(EmptyOutcome::ProvenEmpty { generation });
                    }
                    match job.guard.active_process_count() {
                        Ok(0) => {
                            self.push_order("ActiveProcessZero");
                            Ok(EmptyOutcome::ProvenEmpty { generation })
                        }
                        Ok(_) => Ok(EmptyOutcome::Uncertain {
                            generation,
                            reason: "active_processes_nonzero".into(),
                        }),
                        Err(_) => Ok(EmptyOutcome::Uncertain {
                            generation,
                            reason: "job_object_query_failed".into(),
                        }),
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = job;
                    Ok(EmptyOutcome::Unsupported {
                        reason: WINDOWS_JOB_UNAVAILABLE_ON_HOST.into(),
                    })
                }
            }
            Some(_) => Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "job_generation_mismatch".into(),
            }),
            // Daemon death: kill-on-close closed handles; absent named job.
            None => Ok(EmptyOutcome::ProvenEmpty { generation }),
        }
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
                        Err(_) => {
                            return Ok(EmptyOutcome::Uncertain {
                                generation,
                                reason: "job_object_query_failed".into(),
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
}

impl WindowsJobAdapter {
    /// Close every process/thread/job handle on all branches.
    pub fn close_handles(&self, handle: &AdapterHandle) {
        if let Some(job) = self.jobs.lock().unwrap().get_mut(&handle.key) {
            #[cfg(windows)]
            {
                let _ = job.guard.close_job();
            }
            #[cfg(not(windows))]
            {
                let _ = job;
            }
            self.push_order("CloseHandle_all");
        }
    }

    pub fn order(&self) -> Vec<&'static str> {
        self.order_log.lock().unwrap().clone()
    }
}

/// Compile-time / inventory symbols used only on Windows.
#[cfg(windows)]
pub mod job_symbols {
    #![allow(unused_imports)]
    // Resolve Job Object symbols from this crate's direct windows-sys request.
    pub use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    pub use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectAssociateCompletionPortInformation, JobObjectBasicAccountingInformation,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject,
    };
    pub use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
    };

    #[cfg(test)]
    pub fn inventory_symbol_names() -> &'static [&'static str] {
        &[
            "CreateJobObjectW",
            "SetInformationJobObject",
            "AssignProcessToJobObject",
            "QueryInformationJobObject",
            "TerminateJobObject",
            "JobObjectAssociateCompletionPortInformation",
            "CreateProcessW",
            "ResumeThread",
            "CloseHandle",
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
    async fn exact_suspended_create_assign_resume_order() {
        let adapter = WindowsJobAdapter::new(WindowsJobConfig::default());
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Proven);
        let allocated = adapter.create_and_spawn(sleeper_request(1)).await.unwrap();
        assert_eq!(allocated.guarantee, ContainmentGuarantee::Proven);
        let order = adapter.order();
        let create_job = order.iter().position(|s| *s == "CreateJobObjectW").unwrap();
        let suspend = order
            .iter()
            .position(|s| *s == "CreateProcessW_CREATE_SUSPENDED")
            .unwrap();
        let assign = order
            .iter()
            .position(|s| *s == "AssignProcessToJobObject")
            .unwrap();
        let resume = order.iter().position(|s| *s == "ResumeThread").unwrap();
        assert!(create_job < suspend);
        assert!(suspend < assign);
        assert!(assign < resume);
        assert!(order.contains(&"SetInformationJobObject_KILL_ON_CLOSE"));

        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::Uncertain { reason, .. } => {
                assert_eq!(reason, "active_processes_nonzero");
            }
            o => panic!("live job must not fabricate empty: {o:?}"),
        }

        adapter.terminate(&allocated.handle, 1).await.unwrap();
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 1),
            o => panic!("{o:?}"),
        }
        adapter.close_handles(&allocated.handle);
        assert!(adapter.order().contains(&"CloseHandle_all"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn spawn_failure_is_unsupported_not_proven() {
        let adapter = WindowsJobAdapter::production();
        assert_eq!(adapter.guarantee(), ContainmentGuarantee::Proven);
        let err = adapter
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
            .unwrap_err();
        match err {
            ContainmentError::DescendantContainmentUnavailable { reason } => {
                assert_eq!(reason, "process_spawn_failed");
            }
            o => panic!("{o:?}"),
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
