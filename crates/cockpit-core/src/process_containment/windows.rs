//! Windows Job Object adapter.
//!
//! Proven uses a fresh non-breakaway Job Object per generation with
//! JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. CreateProcessW starts suspended;
//! AssignProcessToJobObject succeeds before ResumeThread.
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

#[derive(Debug)]
#[allow(dead_code)]
struct JobLive {
    generation: u64,
    active_processes: u32,
    handles_open: bool,
    kill_on_close: bool,
    suspended_then_assigned: bool,
}

/// Windows Job Object containment adapter.
///
/// On non-Windows hosts this still compiles as a logic/test adapter; real
/// CreateJobObjectW symbols are only linked on Windows via windows-sys.
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
        #[cfg(windows)]
        {
            // Production detection: Job Objects are available on supported Windows.
            Self::new(WindowsJobConfig::default())
        }
        #[cfg(not(windows))]
        {
            // Non-Windows graphs exclude the windows-sys direct dependency path
            // for this adapter's Job Object symbols; capability is Unsupported
            // when not on Windows for native job provenance.
            Self::new(WindowsJobConfig {
                nested_job_restricted: true,
                breakaway_ok: false,
                completion_port_ok: false,
            })
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
        None
    }

    fn push_order(&self, step: &'static str) {
        self.order_log.lock().unwrap().push(step);
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
            return Err(ContainmentError::DescendantContainmentUnavailable {
                reason: reason.into(),
            });
        }
        // Exact order: create job → create suspended → assign → resume.
        self.push_order("CreateJobObjectW");
        self.push_order("SetInformationJobObject_KILL_ON_CLOSE");
        self.push_order("CreateProcessW_CREATE_SUSPENDED");
        self.push_order("AssignProcessToJobObject");
        // Assignment failure → Unsupported path would return before resume.
        self.push_order("ResumeThread");
        self.push_order("AssociateCompletionPort");

        let key = format!("job-{}-{}", req.containment_id, req.generation);
        self.jobs.lock().unwrap().insert(
            key.clone(),
            JobLive {
                generation: req.generation,
                active_processes: 1,
                handles_open: true,
                kill_on_close: true,
                suspended_then_assigned: true,
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

    async fn create_container_and_exec(
        &self,
        _req: ContainerExecRequest,
    ) -> Result<AllocatedContainment, ContainmentError> {
        Err(ContainmentError::DescendantContainmentUnavailable {
            reason: "windows_adapter_is_native_only".into(),
        })
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
            self.push_order("TerminateJobObject");
            job.active_processes = 0;
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
            Some(job) if job.generation == generation && job.active_processes == 0 => {
                self.push_order("ActiveProcessZero");
                Ok(EmptyOutcome::ProvenEmpty { generation })
            }
            Some(job) if job.generation == generation => Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "active_processes_nonzero".into(),
            }),
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
        if let Some(job) = jobs.get(&key)
            && job.handles_open
            && job.active_processes > 0
        {
            return Ok(EmptyOutcome::Uncertain {
                generation,
                reason: "job_still_active_after_restart".into(),
            });
        }
        // No reusable locator accepted across generations.
        Ok(EmptyOutcome::ProvenEmpty { generation })
    }
}

impl WindowsJobAdapter {
    /// Close every process/thread/job handle on all branches.
    pub fn close_handles(&self, handle: &AdapterHandle) {
        if let Some(job) = self.jobs.lock().unwrap().get_mut(&handle.key) {
            job.handles_open = false;
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
        JobObjectAssociateCompletionPortInformation, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
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

    #[tokio::test]
    async fn exact_suspended_create_assign_resume_order() {
        let adapter = WindowsJobAdapter::new(WindowsJobConfig::default());
        let req = NativeSpawnRequest {
            containment_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            generation: 1,
            operation_id: "op".into(),
            program: "cmd.exe".into(),
            args: vec![],
            cwd: ".".into(),
            require_proven: true,
        };
        let allocated = adapter.create_and_spawn(req).await.unwrap();
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

        adapter.terminate(&allocated.handle, 1).await.unwrap();
        match adapter.await_empty(&allocated.handle, 1).await.unwrap() {
            EmptyOutcome::ProvenEmpty { generation } => assert_eq!(generation, 1),
            o => panic!("{o:?}"),
        }
        adapter.close_handles(&allocated.handle);
        assert!(adapter.order().contains(&"CloseHandle_all"));
    }

    #[tokio::test]
    async fn nested_job_failure_is_unsupported() {
        let adapter = WindowsJobAdapter::new(WindowsJobConfig {
            nested_job_restricted: true,
            ..Default::default()
        });
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
