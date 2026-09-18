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
        Self::prepare_named(pipe_name, true)
    }

    pub fn bind(identity_path: &Path) -> Result<Self> {
        let listener = Self::prepare()?;
        listener.publish(identity_path)?;
        Ok(listener)
    }

    pub fn bind_named(
        identity_path: &Path,
        pipe_name: PipeName,
        first_instance: bool,
    ) -> Result<Self> {
        let listener = Self::prepare_named(pipe_name, first_instance)?;
        listener.publish(identity_path)?;
        Ok(listener)
    }

    pub fn prepare_named(pipe_name: PipeName, first_instance: bool) -> Result<Self> {
        let mut security =
            OwnerOnlyPipeSecurity::for_current_user().context("building owner-only pipe DACL")?;
        let pending = create_server(&pipe_name, first_instance, &mut security)?;
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
    use std::process::{Command, Output};

    const CHILD_MODE_ENV: &str = "COCKPIT_WINDOWS_PIPE_TEST_MODE";
    const CHILD_PIPE_ENV: &str = "COCKPIT_WINDOWS_PIPE_TEST_NAME";
    const CHILD_SID_ENV: &str = "COCKPIT_WINDOWS_PIPE_TEST_SID";
    const COMPETING_FIRST_INSTANCE_MODE: &str = "competing-first-instance";
    const REMOTE_CLIENT_MODE: &str = "remote-client";

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
    async fn second_same_user_process_cannot_create_competing_first_instance() {
        if child_mode() == Some(COMPETING_FIRST_INSTANCE_MODE) {
            assert_child_has_parent_sid();
            let pipe = child_pipe_name();
            let error = match NamedPipeListener::prepare_named(pipe, true) {
                Ok(_) => panic!("second process created a competing first pipe instance"),
                Err(error) => error,
            };
            assert_eq!(
                error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error),
                Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32),
                "competing FIRST_PIPE_INSTANCE must fail with access denied: {error:#}"
            );
            return;
        }

        let listener = NamedPipeListener::prepare().expect("prepare first listener");
        let sid = current_user_sid().expect("parent SID");
        let output = run_test_child(
            "second_same_user_process_cannot_create_competing_first_instance",
            COMPETING_FIRST_INSTANCE_MODE,
            listener.pipe_name(),
            &sid,
        );
        assert_child_succeeded(output, "competing first-instance probe");
    }

    #[tokio::test]
    async fn remote_client_is_rejected() {
        if child_mode() == Some(REMOTE_CLIENT_MODE) {
            use windows_sys::Win32::Foundation::{
                CloseHandle, ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE,
            };
            use windows_sys::Win32::Storage::FileSystem::{
                CreateFileW, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING, SYNCHRONIZE,
            };

            assert_child_has_parent_sid();
            let pipe = child_pipe_name();
            let remote_name = pipe
                .as_str()
                .replacen("\\\\.\\pipe\\", "\\\\127.0.0.1\\pipe\\", 1);
            let wide: Vec<u16> = remote_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();
            // SAFETY: `wide` is a live NUL-terminated UNC pipe path. A valid
            // returned handle is closed below before the assertion fails.
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
            if handle != INVALID_HANDLE_VALUE {
                // SAFETY: CreateFileW returned this owned handle.
                unsafe { CloseHandle(handle) };
                panic!("remote UNC client unexpectedly opened the local-only pipe");
            }
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(ERROR_ACCESS_DENIED as i32),
                "PIPE_REJECT_REMOTE_CLIENTS must reject the UNC client"
            );
            return;
        }

        let listener = NamedPipeListener::prepare().expect("prepare local-only listener");
        let sid = current_user_sid().expect("parent SID");
        let output = run_test_child(
            "remote_client_is_rejected",
            REMOTE_CLIENT_MODE,
            listener.pipe_name(),
            &sid,
        );
        assert_child_succeeded(output, "remote-client probe");
    }

    fn child_mode() -> Option<&'static str> {
        match std::env::var(CHILD_MODE_ENV).as_deref() {
            Ok(COMPETING_FIRST_INSTANCE_MODE) => Some(COMPETING_FIRST_INSTANCE_MODE),
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

    fn assert_child_has_parent_sid() {
        assert_eq!(
            current_user_sid().expect("child SID"),
            std::env::var(CHILD_SID_ENV).expect("parent SID"),
            "pipe probe must run as the daemon's OS user"
        );
    }

    fn run_test_child(test_filter: &str, mode: &str, pipe: &PipeName, sid: &str) -> Output {
        Command::new(std::env::current_exe().expect("current test executable"))
            .arg(test_filter)
            .arg("--nocapture")
            .env(CHILD_MODE_ENV, mode)
            .env(CHILD_PIPE_ENV, pipe.as_str())
            .env(CHILD_SID_ENV, sid)
            .output()
            .expect("run Windows named-pipe test child")
    }

    fn assert_child_succeeded(output: Output, context: &str) {
        assert!(
            output.status.success(),
            "{context} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
