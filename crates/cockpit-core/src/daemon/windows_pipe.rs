//! Windows named-pipe listener for the local daemon control (and reveal) endpoint.
//!
//! Publication is the owner-only identity file at `DaemonPaths.socket`. The
//! listen name is never a well-known global pipe; see `cockpit_host::named_pipe`.

use std::path::Path;

use anyhow::{Context, Result};
use cockpit_host::named_pipe::{
    OwnerOnlyPipeSecurity, PipeName, allocate_pipe_name, current_user_sid, write_pipe_identity,
};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

/// Bound the number of kernel pipe instances instead of accepting Windows'
/// `PIPE_UNLIMITED_INSTANCES` default. Connected clients and the one pending
/// accept instance all count against this defense-in-depth cap.
const PIPE_INSTANCE_POOL_SIZE: usize = 64;

pub struct NamedPipeListener {
    pipe_name: PipeName,
    pending: Option<NamedPipeServer>,
    security: OwnerOnlyPipeSecurity,
}

impl NamedPipeListener {
    /// Allocate and bind a private control pipe without publishing its
    /// filesystem identity. The caller may prepare required sibling endpoints
    /// first and then make this listener observable with [`Self::publish`].
    pub fn prepare() -> Result<Self> {
        let sid = current_user_sid().context("reading current-user SID for pipe ACL")?;
        let pipe_name = allocate_pipe_name(&sid)?;
        Self::prepare_named(pipe_name)
    }

    pub fn bind(identity_path: &Path) -> Result<Self> {
        let listener = Self::prepare()?;
        listener.publish(identity_path)?;
        Ok(listener)
    }

    pub fn bind_named(identity_path: &Path, pipe_name: PipeName) -> Result<Self> {
        let listener = Self::prepare_named(pipe_name)?;
        listener.publish(identity_path)?;
        Ok(listener)
    }

    /// Create the listener's first pipe instance with
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE`. While any instance of `pipe_name`
    /// exists — including one created by another same-user process — this
    /// fails closed with `ERROR_ACCESS_DENIED`, so the daemon can never
    /// silently multiplex onto a squatted name. Creating further instances of
    /// an already-owned name (the accept re-arm path) remains allowed for the
    /// pipe owner; the OS user is the boundary, not the process.
    pub fn prepare_named(pipe_name: PipeName) -> Result<Self> {
        let mut security =
            OwnerOnlyPipeSecurity::for_current_user().context("building owner-only pipe DACL")?;
        let pending = create_server(&pipe_name, true, &mut security)?;
        Ok(Self {
            pipe_name,
            pending: Some(pending),
            security,
        })
    }

    /// Publish the already-bound listener. This identity file is the Windows
    /// readiness boundary; no client can discover the random pipe name before
    /// this succeeds.
    pub fn publish(&self, identity_path: &Path) -> Result<()> {
        write_pipe_identity(identity_path, &self.pipe_name)
    }

    pub fn pipe_name(&self) -> &PipeName {
        &self.pipe_name
    }

    pub async fn accept(&mut self) -> Result<NamedPipeServer> {
        let server = match self.pending.take() {
            Some(server) => server,
            None => create_server(&self.pipe_name, false, &mut self.security)?,
        };
        server
            .connect()
            .await
            .with_context(|| format!("accepting on {}", self.pipe_name.as_str()))?;
        // Create the next pending instance before returning the connected
        // handle. If this fails, `server` is dropped with the `?` and the
        // just-connected client is disconnected; callers see the bind error
        // rather than a half-published identity. Dropping `accept` mid-connect
        // similarly destroys the only pending instance until the loop retries.
        self.pending = Some(create_server(&self.pipe_name, false, &mut self.security)?);
        Ok(server)
    }
}

fn create_server(
    pipe_name: &PipeName,
    first_instance: bool,
    security: &mut OwnerOnlyPipeSecurity,
) -> Result<NamedPipeServer> {
    // SAFETY: `security.as_mut_ptr()` points at a live SECURITY_ATTRIBUTES
    // whose descriptor is owned by `security` for the duration of this call.
    // Tokio requires the pointer to remain valid until CreateNamedPipeW returns.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first_instance)
            .reject_remote_clients(true)
            .max_instances(PIPE_INSTANCE_POOL_SIZE)
            .create_with_security_attributes_raw(pipe_name.as_str(), security.as_mut_ptr())
    }
    .with_context(|| format!("creating named pipe {}", pipe_name.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_host::named_pipe::pipe_is_listening;
    use std::io::Read;
    use std::process::{Child, Command, Output, Stdio};
    use std::time::{Duration, Instant};

    const CHILD_MODE_ENV: &str = "COCKPIT_WINDOWS_PIPE_TEST_MODE";
    const CHILD_PIPE_ENV: &str = "COCKPIT_WINDOWS_PIPE_TEST_NAME";
    const CHILD_CONTROL_PIPE_ENV: &str = "COCKPIT_WINDOWS_PIPE_TEST_CONTROL_NAME";
    const CHILD_SID_ENV: &str = "COCKPIT_WINDOWS_PIPE_TEST_SID";
    /// Completion marker every child mode prints after its assertions pass.
    /// The parent requires it, so an `--exact` filter that matches no test
    /// (zero tests run, exit 0) fails instead of passing vacuously.
    const CHILD_SENTINEL_PREFIX: &str = "cockpit-windows-pipe-child-ok ";
    const SQUAT_FIRST_INSTANCE_MODE: &str = "squat-first-instance";
    const REMOTE_CLIENT_MODE: &str = "remote-client";
    /// Bound on each child run. A `CreateFileW` on `\\127.0.0.1\pipe\...` can
    /// block in the SMB redirector; the parent kills the child and fails the
    /// test instead of waiting forever.
    const CHILD_DEADLINE: Duration = Duration::from_secs(30);
    const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(100);
    const SQUAT_READY_DEADLINE: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn listener_uses_fixed_non_inheritable_instance_pool() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};

        let listener = NamedPipeListener::prepare().expect("prepare listener");
        let pending = listener.pending.as_ref().expect("pending server instance");
        assert_eq!(
            pending.info().expect("pipe info").max_instances,
            PIPE_INSTANCE_POOL_SIZE as u32
        );

        let mut flags = 0_u32;
        // SAFETY: `pending` owns a live named-pipe server handle and `flags`
        // is a valid out pointer.
        let ok = unsafe { GetHandleInformation(pending.as_raw_handle() as HANDLE, &mut flags) };
        assert_ne!(
            ok,
            0,
            "GetHandleInformation: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(
            flags & HANDLE_FLAG_INHERIT,
            0,
            "daemon pipe handles must not be inheritable"
        );
    }

    #[tokio::test]
    async fn first_instance_claim_fails_closed_on_squatted_pipe_name() {
        if child_mode() == Some(SQUAT_FIRST_INSTANCE_MODE) {
            assert_child_has_parent_sid();
            let pipe = child_pipe_name();
            // The squatter deliberately does not claim first-instance
            // ownership: creating an instance of a free name is exactly what
            // the owner-only DACL allows a same-user process to do. The
            // daemon's defense is that its own construction fails closed, not
            // that same-user instance creation is denied.
            let mut security =
                OwnerOnlyPipeSecurity::for_current_user().expect("squatter pipe DACL");
            let squat = create_server(&pipe, false, &mut security)
                .expect("same-user squatter creates an unclaimed instance");
            child_sentinel(SQUAT_FIRST_INSTANCE_MODE);
            hold_until_parent_releases();
            drop(squat);
            return;
        }

        let sid = current_user_sid().expect("parent SID");
        let pipe_name = allocate_pipe_name(&sid).expect("allocate pipe name");
        let child = TestChild::spawn(SQUAT_FIRST_INSTANCE_MODE, &pipe_name, None, &sid);
        wait_pipe_listening(&pipe_name);
        // Production construction claims FILE_FLAG_FIRST_PIPE_INSTANCE and
        // must fail closed while any same-user instance of the name exists.
        let error = match NamedPipeListener::prepare_named(pipe_name.clone()) {
            Ok(listener) => panic!(
                "production construction silently multiplexed onto the squatted name {}",
                listener.pipe_name().as_str()
            ),
            Err(error) => error,
        };
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error),
            Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32),
            "squatting the identity pipe name must be refused: {error:#}"
        );
        // Control proving the denial above is the first-instance claim and
        // not the DACL refusing the owner instance creation: without the
        // claim, the same user can still create an instance of the held name.
        // That is the listener re-arm contract; the OS user is the boundary.
        let mut security = OwnerOnlyPipeSecurity::for_current_user().expect("parent pipe DACL");
        create_server(&pipe_name, false, &mut security)
            .expect("same-user unclaimed instance creation still succeeds");
        child.finish(SQUAT_FIRST_INSTANCE_MODE);
    }

    #[tokio::test]
    async fn remote_client_is_rejected() {
        if child_mode() == Some(REMOTE_CLIENT_MODE) {
            assert_child_has_parent_sid();
            // Negative control: a pipe created without
            // PIPE_REJECT_REMOTE_CLIENTS must not fail the same UNC probe
            // with access denied. If it did, this host rejects loopback pipe
            // clients regardless of the flag and the assertion below would
            // prove nothing.
            let control = open_pipe_via_loopback_unc(&child_control_pipe_name());
            assert_ne!(
                control.err().and_then(|error| error.raw_os_error()),
                Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32),
                "UNC probe of the control pipe must not be access denied"
            );
            let error = open_pipe_via_loopback_unc(&child_pipe_name())
                .expect_err("remote UNC client must be rejected by the daemon pipe");
            assert_eq!(
                error.raw_os_error(),
                Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32),
                "PIPE_REJECT_REMOTE_CLIENTS must reject the UNC client"
            );
            child_sentinel(REMOTE_CLIENT_MODE);
            return;
        }

        let sid = current_user_sid().expect("parent SID");
        let listener = NamedPipeListener::prepare().expect("prepare local-only listener");
        let control_name = allocate_pipe_name(&sid).expect("allocate control pipe name");
        let control =
            create_remote_capable_instance(&control_name).expect("create control pipe instance");
        TestChild::spawn(
            REMOTE_CLIENT_MODE,
            listener.pipe_name(),
            Some(&control_name),
            &sid,
        )
        .finish(REMOTE_CLIENT_MODE);
        drop(control);
    }

    fn child_mode() -> Option<&'static str> {
        match std::env::var(CHILD_MODE_ENV).as_deref() {
            Ok(SQUAT_FIRST_INSTANCE_MODE) => Some(SQUAT_FIRST_INSTANCE_MODE),
            Ok(REMOTE_CLIENT_MODE) => Some(REMOTE_CLIENT_MODE),
            _ => None,
        }
    }

    fn child_pipe_name() -> PipeName {
        cockpit_host::named_pipe::parse_pipe_name(
            std::env::var(CHILD_PIPE_ENV).expect("child pipe name"),
        )
        .expect("valid child pipe name")
    }

    fn child_control_pipe_name() -> PipeName {
        cockpit_host::named_pipe::parse_pipe_name(
            std::env::var(CHILD_CONTROL_PIPE_ENV).expect("child control pipe name"),
        )
        .expect("valid child control pipe name")
    }

    fn assert_child_has_parent_sid() {
        assert_eq!(
            current_user_sid().expect("child SID"),
            std::env::var(CHILD_SID_ENV).expect("parent SID"),
            "pipe probe must run as the daemon's OS user"
        );
    }

    fn child_sentinel(mode: &str) {
        // `--nocapture` puts this on the piped stdout the parent asserts on.
        println!("{CHILD_SENTINEL_PREFIX}{mode}");
    }

    /// Block the child until the parent releases its stdin, so a squat
    /// instance stays alive while the parent probes the held name.
    fn hold_until_parent_releases() {
        let mut sink = Vec::new();
        let _ = std::io::stdin().lock().read_to_end(&mut sink);
    }

    fn wait_pipe_listening(pipe: &PipeName) {
        let deadline = Instant::now() + SQUAT_READY_DEADLINE;
        while !pipe_is_listening(pipe) {
            assert!(
                Instant::now() < deadline,
                "squatter child never created an instance of {}",
                pipe.as_str()
            );
            std::thread::sleep(CHILD_POLL_INTERVAL);
        }
    }

    /// Open `pipe` through the loopback UNC path (`\\127.0.0.1\pipe\...`)
    /// with exactly the ordinary-client rights. A successful open closes the
    /// handle before returning.
    fn open_pipe_via_loopback_unc(pipe: &PipeName) -> std::io::Result<()> {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING, SYNCHRONIZE,
        };

        let remote_name = pipe
            .as_str()
            .replacen("\\\\.\\pipe\\", "\\\\127.0.0.1\\pipe\\", 1);
        let wide: Vec<u16> = remote_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is a live NUL-terminated UNC pipe path. Any handle
        // CreateFileW returns is closed before returning.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: CreateFileW returned this owned handle.
        unsafe { CloseHandle(handle) };
        Ok(())
    }

    /// Test-only negative control: an instance identical to production
    /// except that it does not set `PIPE_REJECT_REMOTE_CLIENTS`.
    fn create_remote_capable_instance(pipe: &PipeName) -> Result<NamedPipeServer> {
        let mut security =
            OwnerOnlyPipeSecurity::for_current_user().context("building control pipe DACL")?;
        // SAFETY: `security.as_mut_ptr()` points at a live SECURITY_ATTRIBUTES
        // owned by `security` for the duration of this call.
        unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(false)
                .max_instances(PIPE_INSTANCE_POOL_SIZE)
                .create_with_security_attributes_raw(pipe.as_str(), security.as_mut_ptr())
        }
        .with_context(|| format!("creating control pipe {}", pipe.as_str()))
    }

    /// A second same-user copy of this test binary running exactly one test
    /// in a chosen child mode.
    struct TestChild {
        child: Child,
    }

    impl TestChild {
        fn spawn(
            mode: &'static str,
            pipe: &PipeName,
            control_pipe: Option<&PipeName>,
            sid: &str,
        ) -> Self {
            // Libtest names a test by its module path from the crate root —
            // `daemon::windows_pipe::tests::…`, never crate-qualified — so a
            // `module_path!()` filter (`cockpit_core::daemon::…`) matches zero
            // tests and the child would exit 0 without ever entering its
            // mode. The current test thread's name is exactly the full
            // libtest name, so the filter self-maintains through renames.
            let test_name = std::thread::current()
                .name()
                .expect("libtest names the test thread")
                .to_string();
            let mut command =
                Command::new(std::env::current_exe().expect("current test executable"));
            command
                .arg("--exact")
                .arg(&test_name)
                .arg("--nocapture")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .env(CHILD_MODE_ENV, mode)
                .env(CHILD_PIPE_ENV, pipe.as_str())
                .env(CHILD_SID_ENV, sid);
            if let Some(control_pipe) = control_pipe {
                command.env(CHILD_CONTROL_PIPE_ENV, control_pipe.as_str());
            }
            Self {
                child: command
                    .spawn()
                    .expect("spawn Windows named-pipe test child"),
            }
        }

        /// Release the child's stdin, require exit within `CHILD_DEADLINE`,
        /// then require both a success status and the mode's sentinel. A child
        /// that hangs (for example in the SMB redirector) is killed and fails
        /// the test.
        fn finish(mut self, mode: &str) {
            drop(self.child.stdin.take());
            let deadline = Instant::now() + CHILD_DEADLINE;
            loop {
                match self.child.try_wait().expect("poll test child status") {
                    Some(_) => break,
                    None if Instant::now() < deadline => {
                        std::thread::sleep(CHILD_POLL_INTERVAL);
                    }
                    None => {
                        // Best effort: the child already exited, or it cannot
                        // be terminated and the reaping wait blocks.
                        let _ = self.child.kill();
                        let Output {
                            status,
                            stdout,
                            stderr,
                        } = self
                            .child
                            .wait_with_output()
                            .expect("reap killed test child");
                        panic!(
                            "{mode} test child did not exit within {CHILD_DEADLINE:?} \
                             (killed; status {status})\nstdout:\n{}\nstderr:\n{}",
                            String::from_utf8_lossy(&stdout),
                            String::from_utf8_lossy(&stderr)
                        );
                    }
                }
            }
            let Output {
                status,
                stdout,
                stderr,
            } = self
                .child
                .wait_with_output()
                .expect("collect test child output");
            assert!(
                status.success(),
                "{mode} test child failed with {status}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr)
            );
            assert!(
                String::from_utf8_lossy(&stdout)
                    .contains(&format!("{CHILD_SENTINEL_PREFIX}{mode}")),
                "{mode} test child never reported its completion sentinel; \
                 the --exact filter matched no test"
            );
        }
    }
}
