//! Windows-only temporary-object evidence runner for issue #398.
//!
//! This is intentionally test-only. It measures an ordinary current-user
//! client exchanging with two temporary protected pipes from a second test
//! runner process. It proves the required Windows temporary-object mechanics,
//! but does not select a child-isolation policy or activate a production launch
//! path: the documented finite resource model is still blocked.

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockedResourceClass {
    UnconfinedFilesystemAndDependencies,
    ConfiguredExecutableAndRuntime,
    TemporaryAndWorkspaceResources,
    PtyAndStandardIo,
    ConfiguredNetwork,
    NativeApprovalBoundary,
}

#[cfg(not(windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureOutcome {
    Unavailable { capability: &'static str },
}

#[cfg(not(windows))]
#[test]
fn temporary_object_runner_reports_the_measured_host_capability() {
    let outcome = FixtureOutcome::Unavailable {
        capability: "WindowsHost",
    };
    eprintln!("Windows child-isolation fixture outcome: {outcome:?}");
    assert_eq!(
        outcome,
        FixtureOutcome::Unavailable {
            capability: "WindowsHost",
        },
        "a non-Windows runner cannot create or measure Windows temporary objects"
    );
}

#[cfg(windows)]
mod windows_fixture {
    use std::env;
    use std::ffi::OsString;
    use std::io;
    use std::process::{Child, Command};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use cockpit_host::named_pipe::OwnerOnlyPipeSecurity;
    use windows_sys::Win32::Foundation::{
        CloseHandle, DuplicateHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_IO_PENDING,
        ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_PIPE_CONNECTED, GetHandleInformation,
        GetLastError, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
        DISABLE_MAX_PRIVILEGE, EqualSid, GetTokenInformation, PROTECTED_DACL_SECURITY_INFORMATION,
        SID_AND_ATTRIBUTES, SetKernelObjectSecurity, SetUserObjectSecurity, TOKEN_ASSIGN_PRIMARY,
        TOKEN_DUPLICATE, TOKEN_QUERY, TokenRestrictedSids, WRITE_DAC, WRITE_OWNER,
        WinRestrictedCodeSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE,
        WriteFile,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, CreatePipe, DisconnectNamedPipe,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, WaitNamedPipeW,
    };
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, CloseWindowStation, CreateDesktopW, CreateWindowStationW,
        GetProcessWindowStation, GetThreadDesktop, GetUserObjectInformationW,
        SetProcessWindowStation, UOI_NAME,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateEventW, CreateProcessAsUserW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId,
        GetProcessId, InitializeProcThreadAttributeList, OpenProcess, OpenProcessToken,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_CREATE_PROCESS, PROCESS_DUP_HANDLE,
        PROCESS_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        QueryFullProcessImageNameW, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        STARTUPINFOW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    use super::BlockedResourceClass;

    const SUPERVISOR_PIPE_ENV: &str = "COCKPIT_HOST_398_SUPERVISOR_PIPE";
    const WORKER_PIPE_ENV: &str = "COCKPIT_HOST_398_WORKER_PIPE";
    const SUPERVISOR_PID_ENV: &str = "COCKPIT_HOST_398_SUPERVISOR_PID";
    const WORKER_PID_ENV: &str = "COCKPIT_HOST_398_WORKER_PID";
    const DUPLICATION_SOURCE_PID_ENV: &str = "COCKPIT_HOST_398_DUPLICATION_SOURCE_PID";
    const DUPLICATION_SOURCE_HANDLE_ENV: &str = "COCKPIT_HOST_398_DUPLICATION_SOURCE_HANDLE";
    const HOLDER_TARGET_PID_ENV: &str = "COCKPIT_HOST_398_HOLDER_TARGET_PID";
    const HOLDER_REPORT_PIPE_ENV: &str = "COCKPIT_HOST_398_HOLDER_REPORT_PIPE";
    const INHERITANCE_MODE_ENV: &str = "COCKPIT_HOST_398_INHERITANCE_MODE";
    const EXPECTED_DESKTOP_ENV: &str = "COCKPIT_HOST_398_EXPECTED_DESKTOP";
    const KNOWN_COCKPIT_HANDLE_ENV: &str = "COCKPIT_HOST_398_KNOWN_COCKPIT_HANDLE";
    const CLIENT_PIPE_ACCESS: u32 = FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE;
    const FIXTURE_TIMEOUT: Duration = Duration::from_secs(10);
    const FIXTURE_TIMEOUT_MS: u32 = 10_000;
    const RESTRICTED_CODE_SID: &str = "S-1-5-12";
    const WINDOW_STATION_ALL_ACCESS: u32 = 0x000f_037f;
    const DESKTOP_ALL_ACCESS: u32 = 0x000f_01ff;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FixtureOutcome {
        Blocked {
            ordinary_current_user_exchanges: bool,
            resources: Vec<ResourceClassObservation>,
        },
        Unavailable {
            capability: &'static str,
            os_error: Option<i32>,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ResourceClassObservation {
        class: BlockedResourceClass,
        outcome: ResourceClassOutcome,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ResourceClassOutcome {
        NoDocumentedAllowRule,
    }

    struct TemporaryPipe(HANDLE);

    /// A pending `ConnectNamedPipeW` keeps one protected server instance
    /// listening while the restricted fixture attempts its client open.  The
    /// guard owns the event and cancels/drains its one overlapped operation
    /// before the pipe can be disconnected or closed.
    struct PendingPipeConnection<'pipe> {
        pipe: &'pipe TemporaryPipe,
        overlapped: windows_sys::Win32::System::IO::OVERLAPPED,
    }

    impl TemporaryPipe {
        fn create(name: &str, security: &mut OwnerOnlyPipeSecurity) -> io::Result<Self> {
            let wide = wide(name);
            // SAFETY: `wide` is a NUL-terminated temporary pipe name and the
            // descriptor is live through CreateNamedPipeW. The returned handle
            // is owned by TemporaryPipe on success.
            let handle = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                    windows_sys::Win32::System::Pipes::PIPE_UNLIMITED_INSTANCES,
                    1024,
                    1024,
                    0,
                    security.as_mut_ptr().cast(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(handle))
        }

        fn exchange(&self, request: &[u8], response: &[u8]) -> io::Result<()> {
            let result = (|| {
                self.connect_with_timeout()?;
                let received = read_exact(self.0, request.len())?;
                if received != request {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "temporary pipe client sent an unexpected request",
                    ));
                }
                write_all(self.0, response)
            })();
            unsafe { DisconnectNamedPipe(self.0) };
            result
        }

        fn receive_then_ack(&self, length: usize) -> io::Result<Vec<u8>> {
            let result = (|| {
                self.connect_with_timeout()?;
                let received = read_exact(self.0, length)?;
                write_all(self.0, b"ok")?;
                Ok(received)
            })();
            unsafe { DisconnectNamedPipe(self.0) };
            result
        }

        fn connect_with_timeout(&self) -> io::Result<()> {
            let mut overlapped = windows_sys::Win32::System::IO::OVERLAPPED::default();
            let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
            if event.is_null() {
                return Err(io::Error::last_os_error());
            }
            overlapped.hEvent = event;
            let connected = unsafe { ConnectNamedPipe(self.0, &mut overlapped) };
            let result = if connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                Ok(())
            } else if unsafe { GetLastError() } == ERROR_IO_PENDING {
                wait_for_overlapped(self.0, &mut overlapped).map(|_| ())
            } else {
                Err(io::Error::last_os_error())
            };
            unsafe { CloseHandle(event) };
            result
        }

        fn begin_pending_connection(&self) -> io::Result<PendingPipeConnection<'_>> {
            let mut overlapped = new_overlapped_event()?;
            let connected = unsafe { ConnectNamedPipe(self.0, &mut overlapped) };
            if connected == 0 && unsafe { GetLastError() } == ERROR_IO_PENDING {
                return Ok(PendingPipeConnection {
                    pipe: self,
                    overlapped,
                });
            }

            // There is no ordinary client after `ordinary_current_user_exchange`
            // has reaped it.  A synchronous completion would therefore mean an
            // unexpected client consumed the protected listener rather than
            // leaving it available for the restricted-child DACL proof.
            if connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                unsafe { DisconnectNamedPipe(self.0) };
                unsafe { CloseHandle(overlapped.hEvent) };
                return Err(io::Error::other(
                    "protected pipe listener accepted an unexpected client while arming denial proof",
                ));
            }

            let error = io::Error::last_os_error();
            unsafe { CloseHandle(overlapped.hEvent) };
            Err(error)
        }
    }

    impl PendingPipeConnection<'_> {
        fn cancel_and_drain(&mut self) -> io::Result<()> {
            if self.overlapped.hEvent.is_null() {
                return Ok(());
            }

            if unsafe { windows_sys::Win32::System::IO::CancelIoEx(self.pipe.0, &self.overlapped) }
                == 0
                && unsafe { GetLastError() } != ERROR_NOT_FOUND
            {
                return Err(io::Error::last_os_error());
            }

            let waited = unsafe { WaitForSingleObject(self.overlapped.hEvent, FIXTURE_TIMEOUT_MS) };
            if waited == WAIT_TIMEOUT {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cancelling protected pipe listener timed out",
                ));
            }
            if waited != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }

            let mut transferred = 0_u32;
            let completed = unsafe {
                windows_sys::Win32::System::IO::GetOverlappedResult(
                    self.pipe.0,
                    &self.overlapped,
                    &mut transferred,
                    0,
                )
            };
            let result = if completed != 0 {
                Err(io::Error::other(
                    "protected pipe listener accepted a client during denial proof",
                ))
            } else if unsafe { GetLastError() } == ERROR_OPERATION_ABORTED {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            };
            unsafe { CloseHandle(self.overlapped.hEvent) };
            self.overlapped.hEvent = std::ptr::null_mut();
            result
        }
    }

    impl Drop for PendingPipeConnection<'_> {
        fn drop(&mut self) {
            // Every expected path explicitly drains the listener.  Preserve
            // that invariant on fixture setup/launch failures too; if Windows
            // cannot acknowledge cancellation, retain the OVERLAPPED storage
            // rather than freeing memory that the kernel could still complete.
            if self.cancel_and_drain().is_err() {
                let _ = Box::into_raw(Box::new(std::mem::take(&mut self.overlapped)));
            }
        }
    }

    impl Drop for TemporaryPipe {
        fn drop(&mut self) {
            // SAFETY: this value is the sole owner of its server pipe handle.
            unsafe {
                let _ = DisconnectNamedPipe(self.0);
                let _ = CloseHandle(self.0);
            }
        }
    }

    #[test]
    fn temporary_object_runner_records_measured_endpoint_evidence_or_unavailable() {
        let desktop = match AlternateDesktop::provision() {
            Ok(desktop) => desktop,
            Err(error) => {
                return report_missing_capability_or_fail(
                    "PrivateAlternateWindowStationAndDesktop",
                    error,
                );
            }
        };
        let fixture = match ordinary_current_user_exchange() {
            Ok(fixture) => fixture,
            Err(error) => {
                return report_missing_capability_or_fail(
                    "TemporaryNamedPipesAndTestRunner",
                    error,
                );
            }
        };
        match restricted_child_denials(&fixture, &desktop) {
            Ok(()) => {}
            Err(error) => return report_missing_capability_or_fail("RestrictedChildSetup", error),
        }
        let outcome = FixtureOutcome::Blocked {
            ordinary_current_user_exchanges: true,
            resources: blocked_resource_observations(),
        };

        eprintln!("Windows child-isolation fixture outcome: {outcome:?}");
        match outcome {
            FixtureOutcome::Blocked {
                ordinary_current_user_exchanges,
                resources,
            } => {
                assert!(
                    ordinary_current_user_exchanges,
                    "the result is blocked only after the real ordinary-client exchanges"
                );
                assert_blocked_resource_observations(&resources);
            }
            FixtureOutcome::Unavailable { .. } => {
                unreachable!("unavailable returns before conformance outcome")
            }
        }
    }

    fn blocked_resource_observations() -> Vec<ResourceClassObservation> {
        use BlockedResourceClass::{
            ConfiguredExecutableAndRuntime, ConfiguredNetwork, NativeApprovalBoundary,
            PtyAndStandardIo, TemporaryAndWorkspaceResources, UnconfinedFilesystemAndDependencies,
        };
        [
            UnconfinedFilesystemAndDependencies,
            ConfiguredExecutableAndRuntime,
            TemporaryAndWorkspaceResources,
            PtyAndStandardIo,
            ConfiguredNetwork,
            NativeApprovalBoundary,
        ]
        .into_iter()
        .map(|class| ResourceClassObservation {
            class,
            outcome: ResourceClassOutcome::NoDocumentedAllowRule,
        })
        .collect()
    }

    fn assert_blocked_resource_observations(resources: &[ResourceClassObservation]) {
        assert_eq!(
            resources.len(),
            6,
            "every current Windows resource class is recorded"
        );
        for class in [
            BlockedResourceClass::UnconfinedFilesystemAndDependencies,
            BlockedResourceClass::ConfiguredExecutableAndRuntime,
            BlockedResourceClass::TemporaryAndWorkspaceResources,
            BlockedResourceClass::PtyAndStandardIo,
            BlockedResourceClass::ConfiguredNetwork,
            BlockedResourceClass::NativeApprovalBoundary,
        ] {
            assert!(
                resources.iter().any(|observation| {
                    observation.class == class
                        && observation.outcome == ResourceClassOutcome::NoDocumentedAllowRule
                }),
                "resource class {class:?} was not independently recorded as lacking an allow rule",
            );
        }
    }

    fn report_missing_capability_or_fail(capability: &'static str, error: io::Error) {
        // A capable Windows host must fail closed on an ordinary setup, launch,
        // descriptor, inspection, or Job error. Only the two documented OS
        // signals that the primitive is absent are a typed unavailable result.
        let missing = matches!(error.raw_os_error(), Some(50 | 120));
        assert!(
            missing,
            "required Windows capability {capability} failed on a capable host: {error}"
        );
        let outcome = FixtureOutcome::Unavailable {
            capability,
            os_error: error.raw_os_error(),
        };
        eprintln!("Windows child-isolation fixture outcome: {outcome:?}");
        match outcome {
            FixtureOutcome::Unavailable {
                capability: actual,
                os_error,
            } => {
                assert_eq!(actual, capability);
                assert_eq!(os_error, error.raw_os_error());
            }
            FixtureOutcome::Blocked { .. } => unreachable!(),
        }
    }

    struct EndpointFixture {
        supervisor: TemporaryPipe,
        worker: TemporaryPipe,
        supervisor_name: String,
        worker_name: String,
    }

    /// Disposable ordinary test-runner processes standing in for the process
    /// objects a future supervisor/worker boundary would protect.  The fixture
    /// never changes the test runner's own DACL.
    struct ProcessTargets {
        supervisor: FixtureHolder,
        worker: FixtureHolder,
        duplication_source: FixtureHolder,
        known_worker_handle: usize,
    }

    impl ProcessTargets {
        fn spawn() -> io::Result<Self> {
            let executable = env::current_exe()?;
            let worker =
                FixtureHolder::spawn(&executable, "windows_fixture::fixture_process_holder")?;
            let supervisor =
                FixtureHolder::spawn(&executable, "windows_fixture::fixture_process_holder")?;

            let (report_name, _) = temporary_pipe_names();
            let mut report_security =
                OwnerOnlyPipeSecurity::for_current_user().map_err(io::Error::other)?;
            let report = TemporaryPipe::create(&report_name, &mut report_security)?;
            let duplication_source =
                FixtureHolder::spawn_source(&executable, worker.pid(), &report_name)?;
            let raw_handle = report.receive_then_ack(std::mem::size_of::<usize>())?;
            let known_worker_handle = usize::from_le_bytes(
                raw_handle
                    .try_into()
                    .map_err(|_| io::Error::other("fixture source reported malformed handle"))?,
            );
            if known_worker_handle == 0 || known_worker_handle == INVALID_HANDLE_VALUE as usize {
                return Err(io::Error::other(
                    "fixture source reported an invalid worker process handle",
                ));
            }

            // These are the actual process objects the restricted child opens.
            // Existing trusted launcher handles retain their lifecycle access;
            // no DACL is ever applied to the test runner.
            protect_process_dacl(supervisor.raw_handle())?;
            protect_process_dacl(worker.raw_handle())?;
            // The source owns a pre-existing handle to the protected worker.
            // Give the restricted child only SYNCHRONIZE to this source, so the
            // DuplicateHandle call has a real source process handle but fails
            // its PROCESS_DUP_HANDLE access check.
            protect_duplication_source_dacl(duplication_source.raw_handle())?;

            Ok(Self {
                supervisor,
                worker,
                duplication_source,
                known_worker_handle,
            })
        }
    }

    struct FixtureHolder {
        child: Child,
    }

    struct FixtureHandle(HANDLE);

    impl Drop for FixtureHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: FixtureHandle has unique ownership of this test-only
                // Windows handle and clears it after closing.
                unsafe { CloseHandle(self.0) };
                self.0 = std::ptr::null_mut();
            }
        }
    }

    #[derive(Default)]
    struct FixtureEnvironment {
        previous: Vec<(&'static str, Option<OsString>)>,
    }

    impl FixtureEnvironment {
        fn set(&mut self, name: &'static str, value: impl AsRef<std::ffi::OsStr>) {
            if !self.previous.iter().any(|(saved, _)| *saved == name) {
                self.previous.push((name, env::var_os(name)));
            }
            // SAFETY: this test process owns these unique fixture variables;
            // Drop restores the caller's prior environment on every exit path.
            unsafe { env::set_var(name, value) };
        }
    }

    impl Drop for FixtureEnvironment {
        fn drop(&mut self) {
            for (name, prior) in self.previous.drain(..).rev() {
                // SAFETY: restores the exact process-global state captured by
                // FixtureEnvironment::set for this test-only child launch.
                unsafe {
                    if let Some(value) = prior {
                        env::set_var(name, value);
                    } else {
                        env::remove_var(name);
                    }
                }
            }
        }
    }

    impl FixtureHolder {
        fn spawn(executable: &std::path::Path, test_name: &str) -> io::Result<Self> {
            let child = Command::new(executable)
                .args(["--exact", test_name, "--ignored", "--nocapture"])
                .spawn()?;
            Ok(Self { child })
        }

        fn spawn_source(
            executable: &std::path::Path,
            target_pid: u32,
            report_pipe: &str,
        ) -> io::Result<Self> {
            let child = Command::new(executable)
                .args([
                    "--exact",
                    "windows_fixture::fixture_duplication_source_holder",
                    "--ignored",
                    "--nocapture",
                ])
                .env(HOLDER_TARGET_PID_ENV, target_pid.to_string())
                .env(HOLDER_REPORT_PIPE_ENV, report_pipe)
                .spawn()?;
            Ok(Self { child })
        }

        fn pid(&self) -> u32 {
            self.child.id()
        }

        fn raw_handle(&self) -> HANDLE {
            use std::os::windows::io::AsRawHandle;

            self.child.as_raw_handle().cast()
        }
    }

    impl Drop for FixtureHolder {
        fn drop(&mut self) {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    fn ordinary_current_user_exchange() -> io::Result<EndpointFixture> {
        let (supervisor_name, worker_name) = temporary_pipe_names();
        let mut supervisor_security =
            OwnerOnlyPipeSecurity::for_current_user().map_err(io::Error::other)?;
        let mut worker_security =
            OwnerOnlyPipeSecurity::for_current_user().map_err(io::Error::other)?;
        let supervisor = TemporaryPipe::create(&supervisor_name, &mut supervisor_security)?;
        let worker = TemporaryPipe::create(&worker_name, &mut worker_security)?;
        // A live daemon must re-arm before returning an accepted connection.
        // Exercise the same subsequent CreateNamedPipeW DACL check here, then
        // drop the disposable pending instances before the exchange below.
        drop(TemporaryPipe::create(
            &supervisor_name,
            &mut supervisor_security,
        )?);
        drop(TemporaryPipe::create(&worker_name, &mut worker_security)?);

        let executable = env::current_exe()?;
        let mut child = Command::new(executable)
            .args([
                "--exact",
                "windows_fixture::ordinary_current_user_client",
                "--ignored",
                "--nocapture",
            ])
            .env(SUPERVISOR_PIPE_ENV, &supervisor_name)
            .env(WORKER_PIPE_ENV, &worker_name)
            .spawn()?;

        let exchanges = (|| {
            supervisor.exchange(b"control", b"admitted")?;
            worker.exchange(b"worker", b"connected")
        })();
        if let Err(error) = exchanges {
            terminate_and_reap_child(&mut child, "ordinary temporary-pipe test-runner")?;
            return Err(error);
        }
        wait_for_child_or_terminate(&mut child, "ordinary temporary-pipe test-runner")?;
        Ok(EndpointFixture {
            supervisor,
            worker,
            supervisor_name,
            worker_name,
        })
    }

    fn restricted_child_denials(
        fixture: &EndpointFixture,
        desktop: &AlternateDesktop,
    ) -> io::Result<()> {
        let targets = ProcessTargets::spawn()?;
        // The ordinary exchange disconnected both server instances.  Re-arm
        // each protected endpoint before any restricted child can run, and
        // retain its pending `ConnectNamedPipeW` through both inheritance
        // variants.  That makes `WaitNamedPipeW` a readiness check and leaves
        // `CreateFileW` as the operation that must observe the DACL denial.
        let mut supervisor_listener = fixture.supervisor.begin_pending_connection()?;
        let mut worker_listener = fixture.worker.begin_pending_connection()?;
        let token = FixtureHandle(restricted_code_token()?);
        let executable = env::current_exe()?;
        let command = format!(
            "\"{}\" --exact windows_fixture::restricted_child_denials --ignored --nocapture",
            executable.display()
        );
        // Mark the real temporary supervisor control-pipe server handle
        // inheritable. It is never placed in either child handle mode, so the
        // child can prove that no Cockpit control-pipe handle leaked.
        let known_cockpit_handle = fixture.supervisor.0;
        // SAFETY: this live test-only pipe handle remains owned by fixture;
        // marking it inheritable gives the two launch modes a known marker.
        if unsafe {
            SetHandleInformation(
                known_cockpit_handle,
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let restricted_result = (|| {
            let mut environment = FixtureEnvironment::default();
            environment.set(SUPERVISOR_PIPE_ENV, &fixture.supervisor_name);
            environment.set(WORKER_PIPE_ENV, &fixture.worker_name);
            environment.set(SUPERVISOR_PID_ENV, targets.supervisor.pid().to_string());
            environment.set(WORKER_PID_ENV, targets.worker.pid().to_string());
            environment.set(
                DUPLICATION_SOURCE_PID_ENV,
                targets.duplication_source.pid().to_string(),
            );
            environment.set(
                DUPLICATION_SOURCE_HANDLE_ENV,
                targets.known_worker_handle.to_string(),
            );
            environment.set(EXPECTED_DESKTOP_ENV, &desktop.full_name);
            environment.set(
                KNOWN_COCKPIT_HANDLE_ENV,
                (known_cockpit_handle as usize).to_string(),
            );
            // The empty variant is a separate process creation: no inherited
            // handles and no attribute list are permitted in that proof.
            environment.set(INHERITANCE_MODE_ENV, "none");
            let empty = launch_restricted_suspended(
                token.0,
                &executable,
                &command,
                desktop,
                Inheritance::None,
            );
            let mut empty = empty?;
            let empty_job = prepare_restricted_child(&mut empty, &executable)?;
            resume_and_require_success(&mut empty, empty_job, None)?;

            let mut stdio = FixtureStdio::create()?;
            // This variant has precisely the three standard-I/O endpoints in
            // its explicit handle list. The protected Cockpit pipe remains
            // inheritable only as the known unlisted-leak marker; it is never
            // included in the attribute allowlist.
            environment.set(INHERITANCE_MODE_ENV, "stdio");
            let listed = launch_restricted_suspended(
                token.0,
                &executable,
                &command,
                desktop,
                Inheritance::ExactStdio(&stdio),
            );
            // Creation has copied the three explicit child endpoints. The parent
            // closes its duplicate endpoints before the target is allowed to run.
            stdio.close_child_ends();
            drop(environment);
            // SAFETY: restore the fixture pipe's non-inheritable state before
            // releasing it back to EndpointFixture's Drop implementation.
            let cleared =
                unsafe { SetHandleInformation(known_cockpit_handle, HANDLE_FLAG_INHERIT, 0) };
            drop(token);
            if cleared == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut listed = listed?;
            let listed_job = prepare_restricted_child(&mut listed, &executable)?;
            resume_and_require_success(&mut listed, listed_job, Some(&stdio))
        })();
        let listener_result = supervisor_listener
            .cancel_and_drain()
            .and_then(|()| worker_listener.cancel_and_drain());
        restricted_result?;
        listener_result
    }

    fn restricted_code_token() -> io::Result<HANDLE> {
        let mut source = std::ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &mut source,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = vec![0_u8; 68];
        let mut length = bytes.len() as u32;
        if unsafe {
            CreateWellKnownSid(
                WinRestrictedCodeSid,
                std::ptr::null_mut(),
                bytes.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0
        {
            unsafe { CloseHandle(source) };
            return Err(io::Error::last_os_error());
        }
        let restrict = SID_AND_ATTRIBUTES {
            Sid: bytes.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let mut restricted = std::ptr::null_mut();
        let created = unsafe {
            CreateRestrictedToken(
                source,
                DISABLE_MAX_PRIVILEGE,
                0,
                std::ptr::null(),
                0,
                std::ptr::null(),
                1,
                &restrict,
                &mut restricted,
            )
        };
        unsafe { CloseHandle(source) };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(restricted)
    }

    /// A unique, noninteractive desktop with a protected DACL that grants
    /// access only to this test user and the restricted-code SID. It is never
    /// `WinSta0`, so a successful child launch proves the requested desktop was
    /// actually provisioned before `CreateProcessAsUserW`.
    struct AlternateDesktop {
        window_station: HANDLE,
        desktop: HANDLE,
        full_name: String,
    }

    impl AlternateDesktop {
        fn provision() -> io::Result<Self> {
            let pid = unsafe { GetCurrentProcessId() };
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let station_name = format!("cockpit-host-398-{pid}-{nonce}");
            let desktop_name = "restricted-child";
            let station_wide = wide(&station_name);
            let desktop_wide = wide(desktop_name);
            let mut station_security =
                ProtectedDacl::for_current_user_and_restricted(WINDOW_STATION_ALL_ACCESS)?;
            // SAFETY: the unique name and live protected descriptor remain
            // valid through creation; the returned handle is owned below.
            let station = unsafe {
                CreateWindowStationW(
                    station_wide.as_ptr(),
                    0,
                    WINDOW_STATION_ALL_ACCESS,
                    station_security.as_mut_ptr(),
                )
            };
            if station.is_null() {
                return Err(io::Error::last_os_error());
            }

            let previous = unsafe { GetProcessWindowStation() };
            if previous.is_null() || unsafe { SetProcessWindowStation(station) } == 0 {
                unsafe { CloseWindowStation(station) };
                return Err(io::Error::last_os_error());
            }
            let mut desktop_security =
                match ProtectedDacl::for_current_user_and_restricted(DESKTOP_ALL_ACCESS) {
                    Ok(security) => security,
                    Err(error) => {
                        unsafe {
                            let _ = SetProcessWindowStation(previous);
                            let _ = CloseWindowStation(station);
                        }
                        return Err(error);
                    }
                };
            // SAFETY: while this process is attached to `station`, the desktop
            // is created within that unique station using the protected ACL.
            let desktop = unsafe {
                CreateDesktopW(
                    desktop_wide.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    DESKTOP_ALL_ACCESS,
                    desktop_security.as_mut_ptr(),
                )
            };
            let restored = unsafe { SetProcessWindowStation(previous) };
            if restored == 0 {
                if !desktop.is_null() {
                    unsafe { CloseDesktop(desktop) };
                }
                unsafe { CloseWindowStation(station) };
                return Err(io::Error::last_os_error());
            }
            if desktop.is_null() {
                unsafe { CloseWindowStation(station) };
                return Err(io::Error::last_os_error());
            }

            // The creation descriptors are protected already; apply them again
            // through the user-object API so this fixture proves the active
            // window-station and desktop DACLs are explicitly protected.
            if let Err(error) = station_security
                .apply_to_user_object(station)
                .and_then(|()| desktop_security.apply_to_user_object(desktop))
            {
                unsafe {
                    let _ = CloseDesktop(desktop);
                    let _ = CloseWindowStation(station);
                }
                return Err(error);
            }
            Ok(Self {
                window_station: station,
                desktop,
                full_name: format!("{station_name}\\{desktop_name}"),
            })
        }
    }

    impl Drop for AlternateDesktop {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseDesktop(self.desktop);
                let _ = CloseWindowStation(self.window_station);
            }
        }
    }

    struct ProtectedDacl {
        descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
        attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    }

    impl ProtectedDacl {
        fn for_current_user_and_restricted(access: u32) -> io::Result<Self> {
            let user = cockpit_host::named_pipe::current_user_sid().map_err(io::Error::other)?;
            let sddl = format!(
                "D:P(A;;0x{access:08x};;;{user})(A;;0x{access:08x};;;{RESTRICTED_CODE_SID})"
            );
            Self::from_sddl(&sddl)
        }

        fn for_current_user(access: u32) -> io::Result<Self> {
            let user = cockpit_host::named_pipe::current_user_sid().map_err(io::Error::other)?;
            Self::from_sddl(&format!("D:P(A;;0x{access:08x};;;{user})"))
        }

        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let wide = wide(&sddl);
            let mut descriptor = std::ptr::null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                descriptor,
                attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>(
                    ) as u32,
                    lpSecurityDescriptor: descriptor,
                    bInheritHandle: 0,
                },
            })
        }

        fn as_mut_ptr(&mut self) -> *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            &mut self.attributes
        }

        fn apply_to_user_object(&self, handle: HANDLE) -> io::Result<()> {
            let information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
            if unsafe { SetUserObjectSecurity(handle, &information, self.descriptor) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for ProtectedDacl {
        fn drop(&mut self) {
            if !self.descriptor.is_null() {
                unsafe { windows_sys::Win32::Foundation::LocalFree(self.descriptor.cast()) };
            }
        }
    }

    enum Inheritance<'a> {
        None,
        ExactStdio(&'a FixtureStdio),
    }

    struct FixtureStdio {
        child_stdin: HANDLE,
        child_stdout: HANDLE,
        child_stderr: HANDLE,
        parent_stdin: HANDLE,
        parent_stdout: HANDLE,
        parent_stderr: HANDLE,
    }

    impl FixtureStdio {
        fn create() -> io::Result<Self> {
            let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: 1,
            };
            // CreatePipe returns (read, write): the child reads stdin while
            // the parent writes it; stdout/stderr reverse that direction.
            let (child_stdin, parent_stdin) = anonymous_pipe(&attributes)?;
            // CreatePipe returns (read, write). The child reads stdin and
            // writes stdout/stderr; the parent keeps the opposing endpoints.
            let (parent_stdout, child_stdout) = anonymous_pipe(&attributes)?;
            let (parent_stderr, child_stderr) = anonymous_pipe(&attributes)?;
            for parent in [parent_stdin, parent_stdout, parent_stderr] {
                if unsafe { SetHandleInformation(parent, HANDLE_FLAG_INHERIT, 0) } == 0 {
                    unsafe {
                        let _ = CloseHandle(parent_stdin);
                        let _ = CloseHandle(child_stdin);
                        let _ = CloseHandle(child_stdout);
                        let _ = CloseHandle(parent_stdout);
                        let _ = CloseHandle(child_stderr);
                        let _ = CloseHandle(parent_stderr);
                    }
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(Self {
                child_stdin,
                child_stdout,
                child_stderr,
                parent_stdin,
                parent_stdout,
                parent_stderr,
            })
        }

        fn child_handles(&self) -> [HANDLE; 3] {
            [self.child_stdin, self.child_stdout, self.child_stderr]
        }

        fn close_child_ends(&mut self) {
            unsafe {
                for handle in [
                    &mut self.child_stdin,
                    &mut self.child_stdout,
                    &mut self.child_stderr,
                ] {
                    if !(*handle).is_null() {
                        let _ = CloseHandle(*handle);
                        *handle = std::ptr::null_mut();
                    }
                }
            }
        }

        fn prove_child_stdio(&self) -> io::Result<()> {
            write_all(self.parent_stdin, b"fixture-stdin\n")?;
            let mut transcript = Vec::new();
            while !transcript
                .windows(b"fixture-stdout\n".len())
                .any(|line| line == b"fixture-stdout\n")
            {
                let mut chunk = [0_u8; 256];
                let read = read_with_timeout(self.parent_stdout, &mut chunk)? as usize;
                transcript.extend_from_slice(&chunk[..read]);
                if transcript.len() > 8 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "exact handle-list child stdout omitted its expected bytes",
                    ));
                }
            }
            if transcript.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "exact handle-list child stdout did not carry the expected bytes",
                ));
            }
            Ok(())
        }
    }

    impl Drop for FixtureStdio {
        fn drop(&mut self) {
            unsafe {
                for handle in [
                    self.child_stdin,
                    self.child_stdout,
                    self.child_stderr,
                    self.parent_stdin,
                    self.parent_stdout,
                    self.parent_stderr,
                ] {
                    let _ = CloseHandle(handle);
                }
            }
        }
    }

    fn anonymous_pipe(
        attributes: &windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
    ) -> io::Result<(HANDLE, HANDLE)> {
        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        if unsafe { CreatePipe(&mut read, &mut write, attributes, 65_536) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((read, write))
    }

    fn launch_restricted_suspended(
        token: HANDLE,
        executable: &std::path::Path,
        command: &str,
        desktop: &AlternateDesktop,
        inheritance: Inheritance<'_>,
    ) -> io::Result<PROCESS_INFORMATION> {
        let application = wide(&executable.to_string_lossy());
        let mut command = wide(command);
        let mut desktop_name = wide(&desktop.full_name);
        let mut startup = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: desktop_name.as_mut_ptr(),
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        let created = match inheritance {
            Inheritance::None => unsafe {
                // No child-visible handle and no attribute list: this is the
                // zero-inheritance half of the fixture.
                CreateProcessAsUserW(
                    token,
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    CREATE_SUSPENDED,
                    std::ptr::null(),
                    std::ptr::null(),
                    &startup,
                    &mut process,
                )
            },
            Inheritance::ExactStdio(handles) => {
                startup.dwFlags = STARTF_USESTDHANDLES;
                startup.hStdInput = handles.child_stdin;
                startup.hStdOutput = handles.child_stdout;
                startup.hStdError = handles.child_stderr;
                create_with_exact_stdio_handles(
                    token,
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    &startup,
                    handles,
                    &mut process,
                )
            }
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { GetProcessId(process.hProcess) } != process.dwProcessId {
            unsafe {
                let _ =
                    windows_sys::Win32::System::Threading::TerminateProcess(process.hProcess, 1);
                let _ = CloseHandle(process.hThread);
                let _ = CloseHandle(process.hProcess);
            }
            return Err(io::Error::other(
                "restricted child process identity mismatch",
            ));
        }
        Ok(process)
    }

    fn create_with_exact_stdio_handles(
        token: HANDLE,
        application: *const u16,
        command: *mut u16,
        startup: &STARTUPINFOW,
        handles: &FixtureStdio,
        process: &mut PROCESS_INFORMATION,
    ) -> i32 {
        let mut bytes = 0_usize;
        // SAFETY: documented sizing probe with a null list pointer.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return 0;
        }
        let words = bytes.div_ceil(std::mem::size_of::<usize>());
        let mut storage = vec![0_usize; words];
        let attributes = storage
            .as_mut_ptr()
            .cast::<windows_sys::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_LIST>(
        );
        // SAFETY: storage uses the exact size returned by the probe and remains
        // live until DeleteProcThreadAttributeList below.
        if unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &mut bytes) } == 0 {
            return 0;
        }
        let mut inherited = handles.child_handles();
        let updated = unsafe {
            UpdateProcThreadAttribute(
                attributes,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherited.as_mut_ptr().cast(),
                std::mem::size_of_val(&inherited),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if updated == 0 {
            unsafe { DeleteProcThreadAttributeList(attributes) };
            return 0;
        }
        let mut extended = STARTUPINFOEXW {
            StartupInfo: *startup,
            lpAttributeList: attributes,
        };
        // CreateProcess reads the STARTUPINFOEXW form only when cb identifies
        // that larger structure; STARTUPINFOW's size would ignore the list.
        extended.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // SAFETY: all Windows strings, STARTUPINFOEXW fields, and the exact
        // three inheritable stdio handles remain valid for the system call.
        let created = unsafe {
            CreateProcessAsUserW(
                token,
                application,
                command,
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                std::ptr::null(),
                (&mut extended as *mut STARTUPINFOEXW).cast(),
                process,
            )
        };
        unsafe { DeleteProcThreadAttributeList(attributes) };
        created
    }

    fn inspect_restricted_child(
        process: &PROCESS_INFORMATION,
        expected_image: &std::path::Path,
    ) -> io::Result<()> {
        inspect_restricted_code_token(process.hProcess)?;
        let mut image = vec![0_u16; 32_768];
        let mut length = image.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(process.hProcess, 0, image.as_mut_ptr(), &mut length)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let actual = std::path::PathBuf::from(String::from_utf16_lossy(&image[..length as usize]));
        if actual != expected_image {
            return Err(io::Error::other(format!(
                "restricted child image mismatch: expected {}, got {}",
                expected_image.display(),
                actual.display()
            )));
        }
        Ok(())
    }

    fn prepare_restricted_child(
        process: &mut PROCESS_INFORMATION,
        expected_image: &std::path::Path,
    ) -> io::Result<HANDLE> {
        let prepared = (|| {
            inspect_restricted_child(process, expected_image)?;
            protect_process_dacl(process.hProcess)?;
            assign_and_check_job(process.hProcess)
        })();
        if prepared.is_err() {
            terminate_and_close(process);
        }
        prepared
    }

    fn protect_process_dacl(process: HANDLE) -> io::Result<()> {
        let security = ProtectedDacl::for_current_user(SYNCHRONIZE)?;
        let information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        // SAFETY: `process` is a disposable fixture holder and the descriptor
        // has an explicit protected DACL. The launcher's already-open handle
        // remains usable; later opens by the restricted child are rechecked.
        if unsafe { SetKernelObjectSecurity(process, information, security.descriptor) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn protect_duplication_source_dacl(process: HANDLE) -> io::Result<()> {
        let security = ProtectedDacl::for_current_user_and_restricted(SYNCHRONIZE)?;
        let information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        // SAFETY: this disposable source process retains a valid pre-existing
        // worker handle. The child may open this source only for SYNCHRONIZE,
        // making DuplicateHandle fail its source PROCESS_DUP_HANDLE check.
        if unsafe { SetKernelObjectSecurity(process, information, security.descriptor) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn assign_and_check_job(process: HANDLE) -> io::Result<HANDLE> {
        // SAFETY: unnamed test job, owned by this function until it has checked
        // membership. The child remains suspended throughout the operation.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let checked = (|| {
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { AssignProcessToJobObject(job, process) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut in_job = 0_i32;
            if unsafe { IsProcessInJob(process, job, &mut in_job) } == 0 {
                return Err(io::Error::last_os_error());
            }
            if in_job == 0 {
                return Err(io::Error::other(
                    "suspended restricted child was not in the fixture job",
                ));
            }
            Ok(())
        })();
        if let Err(error) = checked {
            unsafe { CloseHandle(job) };
            return Err(error);
        }
        Ok(job)
    }

    fn resume_and_require_success(
        process: &mut PROCESS_INFORMATION,
        job: HANDLE,
        stdio: Option<&FixtureStdio>,
    ) -> io::Result<()> {
        // SAFETY: the initial thread is still suspended; all token, image,
        // protected-DACL, and job assertions ran before this resume.
        if unsafe { ResumeThread(process.hThread) } == u32::MAX {
            terminate_and_close(process);
            unsafe { CloseHandle(job) };
            return Err(io::Error::last_os_error());
        }
        if let Some(stdio) = stdio {
            if let Err(error) = stdio.prove_child_stdio() {
                terminate_and_close(process);
                unsafe { CloseHandle(job) };
                return Err(error);
            }
        }
        let waited = unsafe { WaitForSingleObject(process.hProcess, FIXTURE_TIMEOUT_MS) };
        if waited == WAIT_TIMEOUT {
            // Reap before dropping the kill-on-close Job or any process handle:
            // a timed-out restricted child must never outlive this fixture.
            unsafe {
                let _ = TerminateProcess(process.hProcess, 1);
                let _ = WaitForSingleObject(process.hProcess, FIXTURE_TIMEOUT_MS);
                let _ = CloseHandle(process.hThread);
                let _ = CloseHandle(process.hProcess);
                let _ = CloseHandle(job);
            }
            process.hThread = std::ptr::null_mut();
            process.hProcess = std::ptr::null_mut();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "restricted fixture child observation timed out",
            ));
        }
        let mut exit = 1_u32;
        let got_exit = unsafe {
            windows_sys::Win32::System::Threading::GetExitCodeProcess(process.hProcess, &mut exit)
        };
        unsafe {
            let _ = CloseHandle(process.hThread);
            let _ = CloseHandle(process.hProcess);
            let _ = CloseHandle(job);
        }
        process.hThread = std::ptr::null_mut();
        process.hProcess = std::ptr::null_mut();
        if waited != windows_sys::Win32::Foundation::WAIT_OBJECT_0 || got_exit == 0 || exit != 0 {
            return Err(io::Error::other(
                "restricted fixture child did not report every denial",
            ));
        }
        Ok(())
    }

    fn terminate_and_close(process: &mut PROCESS_INFORMATION) {
        unsafe {
            let _ = TerminateProcess(process.hProcess, 1);
            let _ = WaitForSingleObject(process.hProcess, FIXTURE_TIMEOUT_MS);
            let _ = CloseHandle(process.hThread);
            let _ = CloseHandle(process.hProcess);
        }
        process.hThread = std::ptr::null_mut();
        process.hProcess = std::ptr::null_mut();
    }

    fn inspect_restricted_code_token(process: HANDLE) -> io::Result<()> {
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut needed = 0_u32;
        unsafe {
            GetTokenInformation(
                token,
                TokenRestrictedSids,
                std::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if needed == 0 {
            unsafe { CloseHandle(token) };
            return Err(io::Error::last_os_error());
        }
        let mut groups = vec![0_u8; needed as usize];
        let got = unsafe {
            GetTokenInformation(
                token,
                TokenRestrictedSids,
                groups.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        unsafe { CloseHandle(token) };
        if got == 0 {
            return Err(io::Error::last_os_error());
        }
        let group = unsafe {
            &*groups
                .as_ptr()
                .cast::<windows_sys::Win32::Security::TOKEN_GROUPS>()
        };
        if group.GroupCount == 0 {
            return Err(io::Error::other(
                "restricted child token has no restricting SID",
            ));
        }
        let mut restricted_code = vec![0_u8; 68];
        let mut length = restricted_code.len() as u32;
        if unsafe {
            CreateWellKnownSid(
                WinRestrictedCodeSid,
                std::ptr::null_mut(),
                restricted_code.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let groups =
            unsafe { std::slice::from_raw_parts(group.Groups.as_ptr(), group.GroupCount as usize) };
        if !groups.iter().any(|candidate| unsafe {
            EqualSid(candidate.Sid, restricted_code.as_mut_ptr().cast()) != 0
        }) {
            return Err(io::Error::other(
                "restricted child token does not carry WinRestrictedCodeSid",
            ));
        }
        Ok(())
    }

    #[test]
    #[ignore = "runs only as the temporary-object fixture child"]
    fn ordinary_current_user_client() {
        let supervisor = env::var(SUPERVISOR_PIPE_ENV).expect("fixture supervisor pipe name");
        let worker = env::var(WORKER_PIPE_ENV).expect("fixture worker pipe name");
        client_exchange(&supervisor, b"control", b"admitted").expect("supervisor exchange");
        client_exchange(&worker, b"worker", b"connected").expect("worker exchange");
    }

    #[test]
    #[ignore = "runs only as the suspended restricted-token fixture child"]
    fn restricted_child_denials() {
        let supervisor = env::var(SUPERVISOR_PIPE_ENV).expect("fixture supervisor pipe name");
        let worker = env::var(WORKER_PIPE_ENV).expect("fixture worker pipe name");
        let supervisor_pid = env::var(SUPERVISOR_PID_ENV)
            .expect("fixture supervisor pid")
            .parse()
            .expect("numeric supervisor pid");
        let worker_pid = env::var(WORKER_PID_ENV)
            .expect("fixture worker pid")
            .parse()
            .expect("numeric worker pid");
        let duplication_source_pid = env::var(DUPLICATION_SOURCE_PID_ENV)
            .expect("fixture duplication source pid")
            .parse()
            .expect("numeric fixture duplication source pid");
        let known_worker_handle = env::var(DUPLICATION_SOURCE_HANDLE_ENV)
            .expect("fixture duplication source handle")
            .parse::<usize>()
            .expect("numeric fixture duplication source handle")
            as HANDLE;
        let inheritance = env::var(INHERITANCE_MODE_ENV).expect("fixture inheritance mode");

        assert_child_desktop_identity();

        assert_client_open_denied(&supervisor);
        assert_client_open_denied(&worker);
        assert_access_denied(create_second_pipe_instance(&supervisor));
        assert_access_denied(create_second_pipe_instance(&worker));
        for (role, pid) in [("supervisor", supervisor_pid), ("worker", worker_pid)] {
            assert_forbidden_process_rights(role, pid);
        }
        assert_duplicate_handle_denied_with_real_source(
            duplication_source_pid,
            known_worker_handle,
        );
        match inheritance.as_str() {
            "none" => assert_zero_inheritance_proof(),
            "stdio" => assert_exact_stdio_inheritance_proof(),
            other => panic!("unexpected fixture inheritance mode {other}"),
        }
    }

    fn assert_forbidden_process_rights(role: &str, pid: u32) {
        for (name, right) in [
            ("PROCESS_DUP_HANDLE", PROCESS_DUP_HANDLE),
            ("PROCESS_CREATE_PROCESS", PROCESS_CREATE_PROCESS),
            ("PROCESS_VM_OPERATION", PROCESS_VM_OPERATION),
            ("PROCESS_VM_READ", PROCESS_VM_READ),
            ("PROCESS_VM_WRITE", PROCESS_VM_WRITE),
            ("WRITE_DAC", WRITE_DAC),
            ("WRITE_OWNER", WRITE_OWNER),
        ] {
            let process = unsafe { OpenProcess(right, 0, pid) };
            if !process.is_null() && process != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(process) };
                panic!(
                    "restricted child unexpectedly opened protected {role} process {pid} for {name}"
                );
            }
            assert_eq!(
                unsafe { GetLastError() },
                ERROR_ACCESS_DENIED,
                "restricted child {role} process {pid} denial for {name} had the wrong error"
            );
        }
    }

    fn assert_duplicate_handle_denied_with_real_source(source_pid: u32, source_handle: HANDLE) {
        // This source process owns `source_handle`, a valid handle to the
        // protected worker created before its DACL was tightened. Its DACL
        // grants this child only SYNCHRONIZE, so OpenProcess returns a real
        // non-null source but DuplicateHandle itself is denied for lacking
        // PROCESS_DUP_HANDLE on that source-process handle.
        let source = unsafe { OpenProcess(SYNCHRONIZE, 0, source_pid) };
        assert!(
            !source.is_null() && source != INVALID_HANDLE_VALUE,
            "restricted child could not open the controlled duplication source"
        );
        let mut duplicated = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                DuplicateHandle(
                    source,
                    source_handle,
                    GetCurrentProcess(),
                    &mut duplicated,
                    0,
                    0,
                    0,
                )
            },
            0,
            "restricted child unexpectedly duplicated the known protected worker handle"
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);
        unsafe { CloseHandle(source) };
    }

    fn assert_zero_inheritance_proof() {
        assert_known_cockpit_handle_is_absent();
    }

    fn assert_exact_stdio_inheritance_proof() {
        use windows_sys::Win32::System::Console::{
            GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };

        let stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        let stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        let stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
        assert!(
            !stdin.is_null() && stdin != INVALID_HANDLE_VALUE,
            "exact stdio handle list did not deliver stdin"
        );
        assert!(
            !stdout.is_null() && stdout != INVALID_HANDLE_VALUE,
            "exact stdio handle list did not deliver stdout"
        );
        assert!(
            !stderr.is_null() && stderr != INVALID_HANDLE_VALUE,
            "exact stdio handle list did not deliver stderr"
        );
        assert_ne!(
            stdin, stdout,
            "stdio handle list must retain distinct stdin/output"
        );
        assert_ne!(
            stdin, stderr,
            "stdio handle list must retain distinct stdin/error"
        );
        assert_known_cockpit_handle_is_absent();
        let mut input = [0_u8; b"fixture-stdin\n".len()];
        std::io::Read::read_exact(&mut std::io::stdin(), &mut input)
            .expect("exact stdin handle-list endpoint reads parent bytes");
        assert_eq!(&input, b"fixture-stdin\n");
        use std::io::Write as _;
        let mut output = std::io::stdout();
        output
            .write_all(b"fixture-stdout\n")
            .expect("exact stdout handle-list endpoint writes parent bytes");
        output.flush().expect("flush fixture stdout");
    }

    fn assert_known_cockpit_handle_is_absent() {
        let handle = env::var(KNOWN_COCKPIT_HANDLE_ENV)
            .expect("known Cockpit marker handle")
            .parse::<usize>()
            .expect("numeric Cockpit marker handle") as HANDLE;
        let mut flags = 0_u32;
        assert_eq!(
            unsafe { GetHandleInformation(handle, &mut flags) },
            0,
            "restricted child inherited a known Cockpit marker handle",
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_HANDLE);
    }

    fn assert_child_desktop_identity() {
        let expected = env::var(EXPECTED_DESKTOP_ENV).expect("expected alternate desktop");
        let (expected_station, expected_desktop) = expected
            .split_once('\\')
            .expect("alternate desktop has station and desktop name");
        let station = unsafe { GetProcessWindowStation() };
        assert!(
            !station.is_null(),
            "restricted child has no process window station"
        );
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        assert!(!desktop.is_null(), "restricted child has no thread desktop");
        assert_eq!(
            user_object_name(station).expect("read restricted child window-station name"),
            expected_station,
            "restricted child attached to an unexpected window station",
        );
        assert_eq!(
            user_object_name(desktop).expect("read restricted child desktop name"),
            expected_desktop,
            "restricted child attached to an unexpected desktop",
        );
    }

    fn user_object_name(handle: HANDLE) -> io::Result<String> {
        let mut bytes = 0_u32;
        unsafe {
            GetUserObjectInformationW(handle, UOI_NAME, std::ptr::null_mut(), 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut name = vec![0_u16; (bytes as usize).div_ceil(std::mem::size_of::<u16>())];
        if unsafe {
            GetUserObjectInformationW(
                handle,
                UOI_NAME,
                name.as_mut_ptr().cast(),
                bytes,
                &mut bytes,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let length = name
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(name.len());
        Ok(String::from_utf16_lossy(&name[..length]))
    }

    fn assert_access_denied(result: io::Result<HANDLE>) {
        match result {
            Ok(handle) => {
                unsafe { CloseHandle(handle) };
                panic!("restricted child unexpectedly opened a protected pipe");
            }
            Err(error) => assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32)),
        }
    }

    fn assert_client_open_denied(name: &str) {
        wait_for_pipe_listener(name)
            .expect("protected pipe must be listening before the DACL open-denial assertion");
        assert_access_denied(open_listening_client_with_exact_rights(name));
    }

    fn create_second_pipe_instance(name: &str) -> io::Result<HANDLE> {
        let wide = wide(name);
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                64,
                64,
                0,
                std::ptr::null(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(handle)
    }

    fn client_exchange(name: &str, request: &[u8], response: &[u8]) -> io::Result<()> {
        let handle = open_client_with_exact_rights(name)?;
        let result = (|| {
            write_all(handle, request)?;
            let received = read_exact(handle, response.len())?;
            if received != response {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "temporary pipe server sent an unexpected response",
                ));
            }
            Ok(())
        })();
        // SAFETY: `open_client_with_exact_rights` returned a unique client
        // handle; this function closes it exactly once.
        unsafe { CloseHandle(handle) };
        result
    }

    #[test]
    #[ignore = "runs only as a disposable protected process-object fixture holder"]
    fn fixture_process_holder() {
        thread::sleep(FIXTURE_TIMEOUT.saturating_mul(3));
    }

    #[test]
    #[ignore = "runs only as the controlled DuplicateHandle source holder"]
    fn fixture_duplication_source_holder() {
        let target_pid = env::var(HOLDER_TARGET_PID_ENV)
            .expect("fixture source target pid")
            .parse()
            .expect("numeric fixture source target pid");
        let report_pipe = env::var(HOLDER_REPORT_PIPE_ENV).expect("fixture source report pipe");
        let target = unsafe { OpenProcess(SYNCHRONIZE, 0, target_pid) };
        assert!(
            !target.is_null() && target != INVALID_HANDLE_VALUE,
            "fixture source could not open its ordinary worker target"
        );
        let result = (|| {
            let report = open_client_with_exact_rights(&report_pipe)?;
            let bytes = (target as usize).to_le_bytes();
            let exchange = (|| {
                write_all(report, &bytes)?;
                let acknowledgement = read_exact(report, 2)?;
                if acknowledgement != b"ok" {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "fixture source received an invalid handle-report acknowledgement",
                    ));
                }
                Ok(())
            })();
            unsafe { CloseHandle(report) };
            exchange
        })();
        result.expect("fixture source reports the worker handle");
        // Keep the source-process handle table alive until the trusted parent
        // terminates/reaps this disposable holder.
        thread::sleep(FIXTURE_TIMEOUT.saturating_mul(3));
        unsafe { CloseHandle(target) };
    }

    fn open_client_with_exact_rights(name: &str) -> io::Result<HANDLE> {
        wait_for_pipe_listener(name)?;
        open_listening_client_with_exact_rights(name)
    }

    fn wait_for_pipe_listener(name: &str) -> io::Result<()> {
        let wide = wide(name);
        // Bound the race with server creation/acceptance. A timed-out ordinary
        // fixture exchange is an assertion failure rather than an indefinite
        // test-runner hang.
        if unsafe { WaitNamedPipeW(wide.as_ptr(), FIXTURE_TIMEOUT_MS) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn open_listening_client_with_exact_rights(name: &str) -> io::Result<HANDLE> {
        let wide = wide(name);
        // SAFETY: `wide` is a NUL-terminated temporary pipe name. The desired
        // access is exactly the ordinary-client DACL contract, not generic
        // read/write, so it cannot request FILE_CREATE_PIPE_INSTANCE.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                CLIENT_PIPE_ACCESS,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(handle)
    }

    fn write_all(handle: HANDLE, bytes: &[u8]) -> io::Result<()> {
        let written = write_with_timeout(handle, bytes)?;
        if written as usize != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "temporary pipe wrote only part of the test exchange",
            ));
        }
        Ok(())
    }

    fn read_exact(handle: HANDLE, length: usize) -> io::Result<Vec<u8>> {
        let mut bytes = vec![0_u8; length];
        let read = read_with_timeout(handle, &mut bytes)?;
        if read as usize != length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "temporary pipe read only part of the test exchange",
            ));
        }
        Ok(bytes)
    }

    fn write_with_timeout(handle: HANDLE, bytes: &[u8]) -> io::Result<u32> {
        let mut overlapped = new_overlapped_event()?;
        let issued = unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                bytes.len() as u32,
                std::ptr::null_mut(),
                &mut overlapped,
            )
        };
        let result = if issued != 0 {
            wait_for_overlapped(handle, &mut overlapped)
        } else if unsafe { GetLastError() } == ERROR_IO_PENDING {
            wait_for_overlapped(handle, &mut overlapped)
        } else {
            Err(io::Error::last_os_error())
        };
        unsafe { CloseHandle(overlapped.hEvent) };
        result
    }

    fn read_with_timeout(handle: HANDLE, bytes: &mut [u8]) -> io::Result<u32> {
        let mut overlapped = new_overlapped_event()?;
        let issued = unsafe {
            ReadFile(
                handle,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                std::ptr::null_mut(),
                &mut overlapped,
            )
        };
        let result = if issued != 0 {
            wait_for_overlapped(handle, &mut overlapped)
        } else if unsafe { GetLastError() } == ERROR_IO_PENDING {
            wait_for_overlapped(handle, &mut overlapped)
        } else {
            Err(io::Error::last_os_error())
        };
        unsafe { CloseHandle(overlapped.hEvent) };
        result
    }

    fn new_overlapped_event() -> io::Result<windows_sys::Win32::System::IO::OVERLAPPED> {
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(windows_sys::Win32::System::IO::OVERLAPPED {
            hEvent: event,
            ..Default::default()
        })
    }

    fn wait_for_overlapped(
        handle: HANDLE,
        overlapped: &mut windows_sys::Win32::System::IO::OVERLAPPED,
    ) -> io::Result<u32> {
        let waited = unsafe { WaitForSingleObject(overlapped.hEvent, FIXTURE_TIMEOUT_MS) };
        if waited == WAIT_TIMEOUT {
            unsafe {
                let _ = windows_sys::Win32::System::IO::CancelIoEx(handle, overlapped);
                let _ = WaitForSingleObject(overlapped.hEvent, FIXTURE_TIMEOUT_MS);
            }
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "temporary named-pipe operation timed out",
            ));
        }
        if waited != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let mut transferred = 0_u32;
        if unsafe {
            windows_sys::Win32::System::IO::GetOverlappedResult(
                handle,
                overlapped,
                &mut transferred,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(transferred)
    }

    fn wait_for_child_or_terminate(child: &mut Child, role: &str) -> io::Result<()> {
        let deadline = Instant::now() + FIXTURE_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait()? {
                return if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other(format!("{role} exited with {status}")))
                };
            }
            if Instant::now() >= deadline {
                terminate_and_reap_child(child, role)?;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{role} observation timed out"),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate_and_reap_child(child: &mut Child, role: &str) -> io::Result<()> {
        let termination = child.kill();
        let reaped = child.wait();
        match (termination, reaped) {
            (_, Ok(_)) => Ok(()),
            (Ok(()), Err(error)) => Err(io::Error::other(format!(
                "terminated {role}, but could not reap it: {error}"
            ))),
            (Err(termination_error), Err(reap_error)) => Err(io::Error::other(format!(
                "could not terminate {role}: {termination_error}; could not reap it: {reap_error}"
            ))),
        }
    }

    fn temporary_pipe_names() -> (String, String) {
        // SAFETY: returns the current test-runner process ID without borrowing
        // or owning a Windows handle.
        let pid = unsafe { GetCurrentProcessId() };
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes the Unix epoch")
            .as_nanos();
        let prefix = format!(r"\\.\pipe\cockpit-host-398-{pid}-{nonce}");
        (format!("{prefix}-supervisor"), format!("{prefix}-worker"))
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[test]
fn platform_contract_retains_the_real_runner_and_route_inventory() {
    let contract = include_str!("../docs/windows-child-isolation-contract.md");

    for required_text in [
        "**Status:** **Blocked — no production activation**",
        "CreateRestrictedToken",
        "PROC_THREAD_ATTRIBUTE_HANDLE_LIST",
        "bInheritHandles = FALSE",
        "bInheritHandles = TRUE",
        "STARTUPINFOW.lpDesktop",
        "Create and ACL a unique alternate window station and desktop before process",
        "process window-station and thread-desktop names",
        "the child process token",
        "QueryFullProcessImageNameW",
        "AssignProcessToJobObject",
        "IsProcessInJob",
        "protects its process DACL",
        "PROCESS_DUP_HANDLE",
        "ordinary-current-user supervisor admission",
        "typed `Unavailable`",
        "ERROR_NOT_SUPPORTED` or `ERROR_CALL_NOT_IMPLEMENTED`",
        "NoDocumentedAllowRule",
        "#399 remains deferred",
        "test-only temporary-object fixture runner",
        "spawns\na second test-runner process",
        "FILE_READ_DATA | FILE_WRITE_DATA |\nSYNCHRONIZE",
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
        "`crates/cockpit-core/src/worktree_orchestration/validation.rs`",
        "`crates/cockpit-core/src/tools/write.rs`",
        "`crates/cockpit-core/src/tools/edit.rs`",
    ] {
        assert!(
            contract.contains(required_text),
            "platform contract lost required conformance gate: {required_text}"
        );
    }
}
