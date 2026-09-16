//! `excoc` — a small reference for FlyCockpit's ephemeral daemon lifecycle.
//!
//! Default `excoc` attaches to a shared daemon, spawning one if this is the
//! first client. The daemon counts elapsed time from the moment it opened.
//! Later clients attach to that same clock. When the last client disconnects,
//! the daemon exits.
//!
//! Module map onto `flycockpitapp`:
//!
//! | this crate     | flycockpitapp analog                                      |
//! |----------------|-----------------------------------------------------------|
//! | [`host`]       | `crates/cockpit-host` (private dirs, pid, child spawn)    |
//! | [`paths`]      | `DaemonPaths` in `crates/cockpit-core`                    |
//! | [`proto`]      | `crates/cockpit-proto` (NDJSON envelopes)                 |
//! | [`client`]     | `crates/cockpit-client`                                   |
//! | [`daemon`]     | daemon accept loop + last-client reaper in `cockpit-core` |
//! | [`lifecycle`]  | `probe_or_spawn` in `crates/cockpit-core`                 |
//! | [`onboard`]    | `cockpit-core::banner` P-51 + first-run add-provider form |

#[cfg(not(unix))]
compile_error!("excoc's daemon socket is Unix-only, matching flycockpitapp");

pub mod client;
pub mod daemon;
pub mod host;
pub mod lifecycle;
pub mod onboard;
pub mod paths;
pub mod proto;
pub mod supervisor;
pub mod tui;

use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use crate::paths::Paths;
use crate::supervisor::{AdminRes, admin_request};

#[derive(Debug)]
enum OnboardArgs {
    Help,
    Run { skip: bool },
}

fn parse_onboard_args<I>(args: I) -> Result<OnboardArgs>
where
    I: IntoIterator<Item = String>,
{
    let mut skip = false;
    for arg in args {
        match arg.as_str() {
            "--skip" => skip = true,
            "-h" | "--help" => return Ok(OnboardArgs::Help),
            other => bail!("unknown onboard option {other:?}\n{USAGE}"),
        }
    }
    Ok(OnboardArgs::Run { skip })
}

const USAGE: &str = "\
excoc — attach-or-spawn reference CLI

Usage:
  excoc           Attach to the shared daemon, starting it if needed.
                  Prints elapsed time since the daemon opened. The daemon
                  exits when the last client disconnects.
  excoc status    Probe the daemon without becoming a lifetime client.
  excoc reset     Hand off to a fresh daemon without dropping uptime.
                  Spawns a successor, moves it onto the shared socket, and
                  tells attached clients to reconnect. The clock keeps
                  climbing across the swap; only the pid changes.
  excoc onboard          P-51 fly-in, then the add-provider form.
                         Does not start the daemon.
  excoc onboard --skip   Provider form only (skip the fly-in).
  excoc tui              Simulated agentic chat TUI (UX demo, no daemon).
  excoc daemon           Run the daemon in the foreground (spawned by `excoc`).

Supervised design (a stable wrapper owns the socket; the worker rolls):
  excoc up        Attach via the supervisor, starting it if needed. Like
                  `excoc`, but the endpoint is owned by a long-lived
                  supervisor, so upgrades and worker crashes keep the socket.
  excoc upgrade   Roll the worker to a new version behind the same socket.
                  Uptime keeps climbing; the worker pid and version change.
  excoc sup-status  Report the supervisor's current worker generation.
  excoc supervise   Run the supervisor in the foreground (spawned by `excoc up`).
  excoc worker      Run a worker (spawned by the supervisor; not for manual use).

Environment:
  EXCOC_HOME      Runtime directory for the socket, pid file, and log.
  EXCOC_TICK_MS   Tick interval in milliseconds (default 1000).
";

pub fn main_entry() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => run_attach().await,
        Some("status") => run_status().await,
        Some("reset") => run_reset().await,
        Some("onboard") => match parse_onboard_args(args)? {
            OnboardArgs::Help => {
                print!("{USAGE}");
                Ok(())
            }
            OnboardArgs::Run { skip } => onboard::run(skip),
        },
        Some("tui") => tui::run(),
        Some("daemon") => daemon::run_foreground().await,
        Some("supervise") => supervisor::run_supervisor().await,
        Some("worker") => daemon::run_worker().await,
        Some("up") => run_up().await,
        Some("upgrade") => run_upgrade().await,
        Some("sup-status") => run_sup_status().await,
        Some("-h" | "--help" | "help") => {
            print!("{USAGE}");
            Ok(())
        }
        Some(other) => bail!("unknown command {other:?}\n{USAGE}"),
    }
}

async fn run_attach() -> Result<()> {
    use client::Update;

    let mut session = lifecycle::attach_or_spawn().await?;
    let tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    println!(
        "connected pid={} opened_at_ms={}",
        session.hello.pid, session.hello.opened_at_unix_ms
    );
    emit_tick(session.snapshot.elapsed_ms, session.snapshot.clients, tty);
    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => break,
            update = session.next_update() => {
                match update? {
                    Update::Tick(tick) => emit_tick(tick.elapsed_ms, tick.clients, tty),
                    Update::Reconnect { successor_pid } => {
                        if tty {
                            println!();
                        }
                        eprintln!("daemon handing off to pid {successor_pid}; reconnecting");
                        // Re-attach onto the promoted successor. It already owns
                        // the canonical socket, so this lands immediately and the
                        // clock keeps climbing.
                        session = lifecycle::attach_or_spawn().await?;
                        println!(
                            "connected pid={} opened_at_ms={}",
                            session.hello.pid, session.hello.opened_at_unix_ms
                        );
                        emit_tick(session.snapshot.elapsed_ms, session.snapshot.clients, tty);
                    }
                    Update::Closed => {
                        if tty {
                            println!();
                        }
                        eprintln!("daemon closed");
                        return Ok(());
                    }
                }
            }
        }
    }
    if tty {
        println!();
    }
    Ok(())
}

async fn run_status() -> Result<()> {
    match client::probe(&paths::Paths::resolve()?).await? {
        Some(snapshot) => {
            println!(
                "running  pid={}  uptime={}s  clients={}",
                snapshot.pid,
                snapshot.elapsed_ms / 1000,
                snapshot.clients
            );
        }
        None => println!("not running"),
    }
    Ok(())
}

async fn run_reset() -> Result<()> {
    let paths = paths::Paths::resolve()?;
    if !paths.socket.exists() {
        println!("not running");
        return Ok(());
    }
    let mut control = match client::Control::connect(&paths.socket).await {
        Ok(control) => control,
        Err(_) => {
            println!("not running");
            return Ok(());
        }
    };
    let old_pid = control.hello.pid;
    let outcome = control.request(proto::Request::Reset).await?;
    println!(
        "reset: daemon {old_pid} -> {} (uptime {}s continuous, clients {})",
        outcome.pid,
        outcome.elapsed_ms / 1000,
        outcome.clients
    );
    Ok(())
}

/// Supervised attach client (`excoc up`). Attaches to the supervisor-owned
/// socket, starting the supervisor if this is the first client, and reconnects
/// across worker upgrades and crashes — but never spawns a worker itself, since
/// rollout is the supervisor's job.
async fn run_up() -> Result<()> {
    use client::Update;

    let paths = Paths::resolve()?;
    let tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let mut client = connect_supervised(&paths).await?;
    print_supervised_connected(&client, tty);
    emit_tick(client.snapshot.elapsed_ms, client.snapshot.clients, tty);
    loop {
        tokio::select! {
            biased;
            _ = tokio::signal::ctrl_c() => break,
            update = client.next_update() => {
                match update? {
                    Update::Tick(tick) => emit_tick(tick.elapsed_ms, tick.clients, tty),
                    Update::Reconnect { .. } => {
                        if tty {
                            println!();
                        }
                        eprintln!("worker draining; reconnecting via supervisor");
                        client = reconnect_supervised(&paths).await?;
                        print_supervised_connected(&client, tty);
                        emit_tick(client.snapshot.elapsed_ms, client.snapshot.clients, tty);
                    }
                    Update::Closed => {
                        // The worker vanished without a graceful handoff (e.g. a
                        // crash). The supervisor respawns it; reattach rather than
                        // exit, unless the supervisor itself is gone.
                        if tty {
                            println!();
                        }
                        eprintln!("worker connection dropped; reconnecting via supervisor");
                        match reconnect_supervised(&paths).await {
                            Ok(next) => {
                                client = next;
                                print_supervised_connected(&client, tty);
                                emit_tick(client.snapshot.elapsed_ms, client.snapshot.clients, tty);
                            }
                            Err(error) => {
                                eprintln!("supervisor unavailable: {error:#}");
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }
    if tty {
        println!();
    }
    Ok(())
}

fn print_supervised_connected(client: &client::Client, tty: bool) {
    if tty {
        // Keep the connected line on its own row above the in-place uptime line.
    }
    println!(
        "connected pid={} worker_v={} gen={} opened_at_ms={}",
        client.hello.pid,
        client.hello.worker_version,
        client.hello.generation,
        client.hello.opened_at_unix_ms
    );
}

/// First-client attach: try the socket, else start the supervisor, then wait.
async fn connect_supervised(paths: &Paths) -> Result<client::Client> {
    if paths.sup_socket.exists()
        && let Ok(client) = client::Client::connect(&paths.sup_socket).await
    {
        return Ok(client);
    }
    // Start the supervisor unless one is already booting.
    let supervisor_booting = host::read_pid_file(&paths.sup_pid).is_some_and(host::process_exists);
    let spawned = if supervisor_booting {
        None
    } else {
        Some(host::spawn_detached_supervisor(paths)?)
    };
    match attach_supervised_within(paths, Duration::from_secs(10), spawned).await {
        Ok(client) => Ok(client),
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

/// Reconnect after a worker swap or crash. Never spawns a worker; gives up only
/// if the supervisor itself has gone away.
async fn reconnect_supervised(paths: &Paths) -> Result<client::Client> {
    attach_supervised_within(paths, Duration::from_secs(8), None).await
}

/// Attach to the supervisor-owned socket within `timeout`. `expected_pid` is the
/// pid of a supervisor we just spawned, if any: during that boot window the pid
/// file may not exist yet, so we treat that process being alive as "supervisor
/// is coming up" and keep waiting instead of fast-failing.
async fn attach_supervised_within(
    paths: &Paths,
    timeout: Duration,
    expected_pid: Option<u32>,
) -> Result<client::Client> {
    let deadline = Instant::now() + timeout;
    let mut backoff = Duration::from_millis(2);
    loop {
        if paths.sup_socket.exists()
            && let Ok(client) = client::Client::connect(&paths.sup_socket).await
        {
            return Ok(client);
        }
        // Fast exit when the supervisor is truly gone (graceful stop removes the
        // socket and pid file), rather than waiting out the whole deadline.
        if !paths.sup_socket.exists() && !supervisor_alive(paths, expected_pid) {
            bail!("supervisor is not running");
        }
        if Instant::now() >= deadline {
            if !supervisor_alive(paths, expected_pid) {
                bail!("supervisor is not running");
            }
            bail!("timed out attaching to supervised socket");
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(50));
    }
}

fn supervisor_alive(paths: &Paths, expected_pid: Option<u32>) -> bool {
    if expected_pid.is_some_and(host::process_exists) {
        return true;
    }
    host::read_pid_file(&paths.sup_pid).is_some_and(host::process_exists)
}

/// Roll the worker to a new version behind the unchanged socket (`excoc upgrade`).
async fn run_upgrade() -> Result<()> {
    let paths = Paths::resolve()?;
    if !paths.sup_ctl.exists() {
        println!("not running");
        return Ok(());
    }
    let response = match admin_request(&paths, supervisor::AdminReq::Upgrade).await {
        Ok(response) => response,
        Err(_) => {
            println!("not running");
            return Ok(());
        }
    };
    match response {
        AdminRes::Rolled {
            old_pid,
            new_pid,
            worker_version,
            generation,
            elapsed_ms,
            ..
        } => {
            println!(
                "upgrade: worker v{}->v{worker_version} (gen {generation}) pid {old_pid} -> {new_pid}, uptime {}s continuous",
                worker_version.saturating_sub(1),
                elapsed_ms / 1000
            );
            Ok(())
        }
        AdminRes::Error { message } => bail!("upgrade failed: {message}"),
        AdminRes::Status { .. } => bail!("supervisor returned a status reply to an upgrade"),
    }
}

/// Report the supervisor's current worker generation (`excoc sup-status`).
async fn run_sup_status() -> Result<()> {
    let paths = Paths::resolve()?;
    if !paths.sup_ctl.exists() {
        println!("not running");
        return Ok(());
    }
    match admin_request(&paths, supervisor::AdminReq::Status).await {
        Ok(AdminRes::Status {
            worker_pid,
            worker_version,
            generation,
            elapsed_ms,
            ..
        }) => {
            println!(
                "running  worker_pid={worker_pid}  v{worker_version}  gen={generation}  uptime={}s",
                elapsed_ms / 1000
            );
            Ok(())
        }
        Ok(AdminRes::Error { message }) => bail!("{message}"),
        Ok(AdminRes::Rolled { .. }) => bail!("supervisor returned a roll reply to a status query"),
        Err(_) => {
            println!("not running");
            Ok(())
        }
    }
}

fn emit_tick(elapsed_ms: u64, clients: usize, tty: bool) {
    let line = format!("uptime {}s  clients {clients}", elapsed_ms / 1000);
    if tty {
        print!("\r{line:<32}");
        let _ = std::io::Write::flush(&mut std::io::stdout());
    } else {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn onboard_with_no_flags_plays_the_animation() {
        match parse_onboard_args(args(&[])).unwrap() {
            OnboardArgs::Run { skip } => assert!(!skip),
            OnboardArgs::Help => panic!("expected a run"),
        }
    }

    #[test]
    fn onboard_skip_jumps_to_the_form() {
        match parse_onboard_args(args(&["--skip"])).unwrap() {
            OnboardArgs::Run { skip } => assert!(skip),
            OnboardArgs::Help => panic!("expected a run"),
        }
    }

    #[test]
    fn onboard_help_flags_are_help() {
        for flag in ["-h", "--help"] {
            assert!(matches!(
                parse_onboard_args(args(&[flag])).unwrap(),
                OnboardArgs::Help
            ));
        }
    }

    #[test]
    fn onboard_rejects_unknown_flags() {
        let error = parse_onboard_args(args(&["--fast"])).unwrap_err();
        assert!(error.to_string().contains("unknown onboard option"));
    }
}
