//! Shared child-process termination helpers.

use std::time::Duration;

#[cfg(unix)]
fn signal_group(pgid: i32, sig: libc::c_int) -> std::io::Result<()> {
    // SAFETY: `libc::kill` with a negative pid signals the process
    // group; passing a valid pgid (== the leader pid, since callers set
    // `process_group(0)`) is sound.
    let rc = unsafe { libc::kill(-pgid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn is_esrch(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ESRCH)
}

pub(crate) async fn terminate_group_async(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    grace: Duration,
) {
    #[cfg(unix)]
    {
        if let Some(pid) = pid.and_then(|pid| i32::try_from(pid).ok()) {
            match signal_group(pid, libc::SIGTERM) {
                Ok(()) => {}
                Err(error) if is_esrch(&error) => {
                    let _ = child.wait().await;
                    return;
                }
                Err(_) => {}
            }
            tokio::select! {
                _ = child.wait() => return,
                _ = tokio::time::sleep(grace) => {
                    let _ = signal_group(pid, libc::SIGKILL);
                }
            }
        } else {
            let _ = child.kill().await;
        }
        let _ = child.wait().await;
    }
    #[cfg(not(unix))]
    {
        let _ = grace;
        let _ = pid;
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

pub(crate) fn terminate_group_sync(child: &mut std::process::Child, grace: Duration) {
    #[cfg(unix)]
    {
        let pgid = child.id() as i32;
        if pgid > 0 {
            match signal_group(pgid, libc::SIGTERM) {
                Ok(()) => {}
                Err(error) if is_esrch(&error) => {
                    let _ = child.wait();
                    return;
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
            }
            let started = std::time::Instant::now();
            while started.elapsed() < grace {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => std::thread::sleep(Duration::from_millis(10).min(grace)),
                    Err(_) => break,
                }
            }
            let _ = signal_group(pgid, libc::SIGKILL);
            let _ = child.wait();
            return;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = grace;
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn wait_for_file(path: &std::path::Path) {
        let start = std::time::Instant::now();
        while !path.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "timed out waiting for {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_group_async_kills_descendant_process_group() {
        let tmp = tempfile::tempdir().unwrap();
        let heartbeat = tmp.path().join("heartbeat");
        let ready = tmp.path().join("ready");
        let script = format!(
            "( while true; do touch '{}'; sleep 0.1; done ) & touch '{}'; sleep 30",
            heartbeat.display(),
            ready.display()
        );
        let mut cmd = tokio::process::Command::new("sh");
        cmd.arg("-c")
            .arg(script)
            .current_dir(tmp.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id();
        wait_for_file(&ready);
        wait_for_file(&heartbeat);

        terminate_group_async(&mut child, pid, Duration::from_millis(200)).await;

        tokio::time::sleep(Duration::from_millis(600)).await;
        let mtime_after_kill = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        tokio::time::sleep(Duration::from_millis(400)).await;
        let mtime_later = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        assert_eq!(
            mtime_after_kill, mtime_later,
            "descendant heartbeat kept updating after process-group termination"
        );
    }
}
