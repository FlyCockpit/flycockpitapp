//! Supervised daemon lifecycle: a **stable wrapper** owns the endpoint while an
//! **upgradable worker** does the work behind it.
//!
//! This is the alternative to the `reset` self-handoff in [`crate::daemon`]. It
//! sketches the "frozen launcher / rolling worker" design:
//!
//! - `excoc supervise` ([`run_supervisor`]) binds the public socket and pid file
//!   **once** and holds them for its whole life. It never serves protocol
//!   traffic; it only spawns and watches worker generations. This is the piece
//!   that is meant to "never change once it is right."
//! - `excoc worker` ([`crate::daemon::run_worker`]) inherits the listening socket
//!   (fd 3) and the durable open time, serves clients, and is the piece that
//!   rolls forward on upgrade. Because the socket lives in the supervisor, it
//!   never closes across a swap: new connections queue in the kernel backlog
//!   instead of failing.
//! - `excoc upgrade` rolls the worker to the next version behind the unchanged
//!   socket. `excoc sup-status` reports the current generation.
//!
//! What this still does **not** do (deliberately, to keep the lesson focused):
//!
//! - **Open connections still blip.** The socket survives, but a client already
//!   attached to the draining/killed worker must reconnect (its connection fd
//!   belonged to that process). Durable session state would live in a store like
//!   SQLite; here the only carried state is the open clock, inherited by env.
//! - **The supervisor is persistent, not ephemeral.** Reaping the supervisor
//!   when the worker reports zero lifetime clients is a natural extension (mirror
//!   [`crate::daemon::ephemeral_last_client_reaper`]), but it must be suppressed
//!   during a roll/respawn to avoid tearing down in the reconnect gap. Left out
//!   here so the demo centers on socket ownership, rolling upgrade, and crash
//!   recovery.

use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::UnixStream;

use crate::host::{self, bind_private_listener_std, bind_private_socket, reserve_pid_file};
use crate::paths::Paths;

/// How long the supervisor waits for a freshly spawned worker to signal readiness
/// before giving up on it.
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the supervisor polls whether its current worker is still alive.
const LIVENESS_POLL: Duration = Duration::from_millis(150);

/// Max control-line length; the admin protocol frames are tiny.
const MAX_CTL_BYTES: usize = 16 * 1024;

/// Admin verbs sent to the supervisor over its control socket. This is the small,
/// deliberately frozen wrapper boundary — distinct from the public NDJSON proto.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdminReq {
    /// Roll the worker to the next version behind the unchanged socket.
    Upgrade,
    /// Report the current worker generation/version and the shared clock.
    Status,
}

/// Admin replies from the supervisor.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdminRes {
    Rolled {
        old_pid: u32,
        new_pid: u32,
        worker_version: u32,
        generation: u32,
        opened_at_unix_ms: u64,
        elapsed_ms: u64,
    },
    Status {
        worker_pid: u32,
        worker_version: u32,
        generation: u32,
        opened_at_unix_ms: u64,
        elapsed_ms: u64,
    },
    Error {
        message: String,
    },
}

/// Cleans the supervisor's pid file and sockets on exit, but only while the pid
/// file still names this process (so a replacement that won a later reservation
/// keeps its files).
struct SupMetadataGuard {
    paths: Paths,
    pid: u32,
}

impl Drop for SupMetadataGuard {
    fn drop(&mut self) {
        if host::read_pid_file(&self.paths.sup_pid) != Some(self.pid) {
            return;
        }
        remove_if_present(&self.paths.sup_pid);
        remove_if_present(&self.paths.sup_socket);
        remove_if_present(&self.paths.sup_ctl);
    }
}

/// Run the supervisor in the foreground (`excoc supervise`).
pub async fn run_supervisor() -> Result<()> {
    let paths = Paths::resolve()?;
    let pid = std::process::id();

    // Win the supervisor identity before touching shared endpoints; only the
    // winner may clear stale sockets.
    reserve_pid_file(&paths.sup_pid, pid)
        .with_context(|| format!("reserving supervisor pid file {}", paths.sup_pid.display()))?;
    let _guard = SupMetadataGuard {
        paths: paths.clone(),
        pid,
    };

    remove_if_present(&paths.sup_socket);
    remove_if_present(&paths.sup_ctl);

    // Bind the public socket ONCE and hold it for the supervisor's whole life.
    // Every worker generation dups this fd; the endpoint never closes.
    let public = bind_private_listener_std(&paths.sup_socket)?;
    let public_fd = public.as_raw_fd();
    let ctl = bind_private_socket(&paths.sup_ctl)?;

    // The durable clock lives in the supervisor and is handed to every worker,
    // so uptime is continuous across upgrades *and* crashes.
    let opened_at = Instant::now();
    let opened_at_unix_ms = now_unix_ms();

    let mut worker_version = 1u32;
    let mut generation = 1u32;
    let mut worker_pid = spawn_and_wait_worker(
        &paths,
        public_fd,
        opened_at_unix_ms,
        worker_version,
        generation,
    )
    .await
    .context("starting the first worker")?;
    eprintln!(
        "excoc supervisor {pid}: worker gen {generation} (v{worker_version}) pid {worker_pid} ready"
    );

    let mut liveness = tokio::time::interval(LIVENESS_POLL);
    liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = liveness.tick() => {
                if !host::process_exists(worker_pid) {
                    // The worker crashed. Respawn the same version with the same
                    // clock — no client asked us to, which is the point: background
                    // work survives a worker crash independent of any attached UI.
                    generation += 1;
                    match spawn_and_wait_worker(
                        &paths, public_fd, opened_at_unix_ms, worker_version, generation,
                    ).await {
                        Ok(new_pid) => {
                            eprintln!(
                                "excoc supervisor {pid}: worker crashed; respawned gen {generation} \
                                 (v{worker_version}) pid {new_pid}"
                            );
                            worker_pid = new_pid;
                        }
                        Err(error) => {
                            eprintln!("excoc supervisor {pid}: respawn failed: {error:#}");
                            generation -= 1;
                        }
                    }
                }
            }
            accepted = ctl.accept() => {
                let (stream, _) = match accepted {
                    Ok(pair) => pair,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error).context("accepting supervisor control client"),
                };
                let mut conn = CtlStream::new(stream);
                let req = match conn.recv::<AdminReq>().await {
                    Ok(Some(req)) => req,
                    Ok(None) | Err(_) => continue,
                };
                match req {
                    AdminReq::Upgrade => {
                        let next_version = worker_version + 1;
                        let next_generation = generation + 1;
                        match spawn_and_wait_worker(
                            &paths, public_fd, opened_at_unix_ms, next_version, next_generation,
                        ).await {
                            Ok(new_pid) => {
                                // Successor is ready and already accepting on the
                                // shared socket. Drain the old worker: it stops
                                // accepting and tells its clients to reconnect,
                                // which now land on the successor.
                                let old_pid = worker_pid;
                                host::terminate(old_pid);
                                worker_version = next_version;
                                generation = next_generation;
                                worker_pid = new_pid;
                                let _ = conn.send(&AdminRes::Rolled {
                                    old_pid,
                                    new_pid,
                                    worker_version,
                                    generation,
                                    opened_at_unix_ms,
                                    elapsed_ms: elapsed_ms(opened_at),
                                }).await;
                            }
                            Err(error) => {
                                let _ = conn.send(&AdminRes::Error {
                                    message: format!("{error:#}"),
                                }).await;
                            }
                        }
                    }
                    AdminReq::Status => {
                        let _ = conn.send(&AdminRes::Status {
                            worker_pid,
                            worker_version,
                            generation,
                            opened_at_unix_ms,
                            elapsed_ms: elapsed_ms(opened_at),
                        }).await;
                    }
                }
            }
        }
    }

    // Graceful stop: drain the worker, then let the guard clear metadata.
    host::terminate(worker_pid);
    drop(public);
    Ok(())
}

/// Spawn a worker and block until it signals readiness (or dies / times out).
async fn spawn_and_wait_worker(
    paths: &Paths,
    listener_fd: std::os::fd::RawFd,
    opened_at_unix_ms: u64,
    worker_version: u32,
    generation: u32,
) -> Result<u32> {
    let (pid, ready) = host::spawn_worker(
        paths,
        listener_fd,
        opened_at_unix_ms,
        worker_version,
        generation,
    )?;
    match wait_ready(ready, WORKER_READY_TIMEOUT).await {
        Ok(true) => Ok(pid),
        Ok(false) => {
            host::terminate(pid);
            bail!("worker pid {pid} exited before signaling ready")
        }
        Err(error) => {
            // Terminating closes the child's write end, unblocking the pending
            // blocking read so nothing leaks.
            host::terminate(pid);
            Err(error)
        }
    }
}

/// Await one readiness byte on the notify pipe. `Ok(true)` = ready, `Ok(false)`
/// = EOF (the worker died during boot), `Err` = timeout.
async fn wait_ready(read: OwnedFd, timeout: Duration) -> Result<bool> {
    let task = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut file = std::fs::File::from(read);
        let mut buf = [0u8; 1];
        match file.read(&mut buf) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(error) => Err(error),
        }
    });
    match tokio::time::timeout(timeout, task).await {
        Ok(join) => join
            .context("readiness wait task panicked")?
            .context("reading worker readiness pipe"),
        Err(_) => bail!("timed out waiting for worker to signal ready"),
    }
}

/// Send an admin request to a running supervisor and read its reply.
pub async fn admin_request(paths: &Paths, req: AdminReq) -> Result<AdminRes> {
    let stream = UnixStream::connect(&paths.sup_ctl).await.with_context(|| {
        format!(
            "connecting to supervisor control {}",
            paths.sup_ctl.display()
        )
    })?;
    let mut conn = CtlStream::new(stream);
    conn.send(&req).await?;
    conn.recv::<AdminRes>()
        .await?
        .context("supervisor closed the control connection without replying")
}

/// Minimal line-delimited JSON channel for the admin control protocol. Kept
/// separate from [`crate::proto::ProtoStream`] to emphasize that the wrapper
/// boundary is its own small, frozen contract.
struct CtlStream {
    reader: BufReader<ReadHalf<UnixStream>>,
    writer: WriteHalf<UnixStream>,
}

impl CtlStream {
    fn new(stream: UnixStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: BufReader::new(reader),
            writer,
        }
    }

    async fn send<T: Serialize>(&mut self, msg: &T) -> Result<()> {
        let mut line = serde_json::to_string(msg).context("serializing control frame")?;
        line.push('\n');
        if line.len() > MAX_CTL_BYTES {
            bail!("outgoing control frame exceeded {MAX_CTL_BYTES} bytes");
        }
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        if line.len() > MAX_CTL_BYTES {
            bail!("incoming control frame exceeded {MAX_CTL_BYTES} bytes");
        }
        let msg = serde_json::from_str(line.trim_end()).context("decoding control frame")?;
        Ok(Some(msg))
    }
}

fn remove_if_present(path: &std::path::Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => eprintln!("excoc supervisor: removing {}: {error}", path.display()),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn elapsed_ms(opened_at: Instant) -> u64 {
    opened_at.elapsed().as_millis() as u64
}
