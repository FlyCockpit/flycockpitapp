//! Attach-or-spawn composition.
//!
//! Analog of `probe_or_spawn` in `crates/cockpit-core`. Discovery always wins:
//! if a daemon is already hellos on the canonical socket, this process attaches
//! and never starts a second owner. Socket-owner shutdown is governed only by
//! the daemon's client reference count, never by this client process.

use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};

use crate::client::{Client, Snapshot, Update};
use crate::host::{self, spawn_detached_daemon};
use crate::paths::Paths;
use crate::proto::Hello;

const SPAWN_DAEMON_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Attached {
    client: Client,
    pub hello: Hello,
    pub snapshot: Snapshot,
}

impl Attached {
    pub async fn next_update(&mut self) -> Result<Update> {
        self.client.next_update().await
    }
}

pub async fn attach_or_spawn() -> Result<Attached> {
    let paths = Paths::resolve()?;
    if let Some(client) = try_attach(&paths).await? {
        return Ok(client);
    }
    let pid = spawn_detached_daemon(&paths, None)?;
    match wait_for_daemon(&paths.socket, Some(pid)).await {
        Ok(attached) => Ok(attached),
        Err(error) => {
            let log = std::fs::read_to_string(&paths.log_file).unwrap_or_default();
            if log.trim().is_empty() {
                Err(error)
            } else {
                bail!("{error:#}\n{}", log.trim())
            }
        }
    }
}

async fn try_attach(paths: &Paths) -> Result<Option<Attached>> {
    if !paths.socket.exists() {
        return Ok(None);
    }
    match Client::connect(&paths.socket).await {
        Ok(client) => Ok(Some(finish_attach(client))),
        Err(_) => {
            if let Some(pid) = host::read_pid_file(&paths.pid_file)
                && host::process_exists(pid)
            {
                Ok(Some(wait_for_daemon(&paths.socket, Some(pid)).await?))
            } else {
                Ok(None)
            }
        }
    }
}

async fn wait_for_daemon(socket: &Path, pid: Option<u32>) -> Result<Attached> {
    let deadline = std::time::Instant::now() + SPAWN_DAEMON_TIMEOUT;
    let mut backoff = Duration::from_millis(2);
    loop {
        if socket.exists()
            && let Ok(client) = Client::connect(socket).await
        {
            return Ok(finish_attach(client));
        }
        if std::time::Instant::now() >= deadline {
            if pid.is_some_and(|pid| !host::process_exists(pid)) {
                bail!(
                    "daemon pid {pid:?} exited before its socket became ready at {}",
                    socket.display()
                );
            }
            bail!("timed out waiting for daemon at {}", socket.display());
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(50));
    }
}

fn finish_attach(client: Client) -> Attached {
    Attached {
        hello: client.hello.clone(),
        snapshot: client.snapshot.clone(),
        client,
    }
}
