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

pub struct NamedPipeListener {
    pipe_name: PipeName,
    pending: Option<NamedPipeServer>,
    security: OwnerOnlyPipeSecurity,
}

impl NamedPipeListener {
    pub fn bind(identity_path: &Path) -> Result<Self> {
        let sid = current_user_sid().context("reading current-user SID for pipe ACL")?;
        let pipe_name = allocate_pipe_name(&sid)?;
        Self::bind_named(identity_path, pipe_name, true)
    }

    pub fn bind_named(
        identity_path: &Path,
        pipe_name: PipeName,
        first_instance: bool,
    ) -> Result<Self> {
        let mut security =
            OwnerOnlyPipeSecurity::for_current_user().context("building owner-only pipe DACL")?;
        let pending = create_server(&pipe_name, first_instance, &mut security)?;
        write_pipe_identity(identity_path, &pipe_name)?;
        Ok(Self {
            pipe_name,
            pending: Some(pending),
            security,
        })
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
            .create_with_security_attributes_raw(pipe_name.as_str(), security.as_mut_ptr())
    }
    .with_context(|| format!("creating named pipe {}", pipe_name.as_str()))
}
