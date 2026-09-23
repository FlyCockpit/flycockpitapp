//! `kill_direct_child_process_groups` kills every direct child and the
//! process group it leads. It signals *all* of this process's children, so it
//! lives alone in its own test binary rather than beside tests that spawn
//! children concurrently in the same process.

#[cfg(unix)]
#[test]
fn kills_direct_children_and_their_process_groups() {
    use std::os::unix::process::CommandExt as _;
    use std::os::unix::process::ExitStatusExt as _;

    // A group leader with an in-group grandchild, like a tool's shell.
    let mut leader = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 30 & echo $!; wait"])
        .process_group(0)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn group leader");
    let mut line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(leader.stdout.take().expect("leader stdout")),
        &mut line,
    )
    .expect("read grandchild pid");
    let grandchild: libc::pid_t = line.trim().parse().expect("grandchild pid");

    assert!(cockpit_host::process::kill_direct_child_process_groups() >= 1);

    let status = leader.wait().expect("reap leader");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    // The grandchild was killed with its group (it may linger as a zombie
    // until its new parent reaps it).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if !running(grandchild) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "in-group grandchild {grandchild} outlived the group kill"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Whether `pid` names a live, non-zombie process.
#[cfg(unix)]
fn running(pid: libc::pid_t) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        let state = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.trim_start().chars().next());
        !matches!(state, None | Some('Z' | 'X'))
    }
    #[cfg(not(target_os = "linux"))]
    {
        // SAFETY: signal 0 only probes existence.
        unsafe { libc::kill(pid, 0) == 0 }
    }
}
