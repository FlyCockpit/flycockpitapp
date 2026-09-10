//! Shared child-process helpers.

use std::{
    sync::{Arc, Mutex, OnceLock, mpsc},
    time::{Duration, Instant},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt},
    task::JoinHandle,
};

#[cfg(target_os = "linux")]
use std::os::unix::{ffi::OsStrExt as _, process::ExitStatusExt as _};

/// Default retained bytes per child-process pipe.
pub const CHILD_PIPE_CAPTURE_BYTES: usize = 256 * 1024;
/// Head budget for command tools that need both the beginning and end of output.
pub const CHILD_PIPE_CAPTURE_HEAD_BYTES: usize = CHILD_PIPE_CAPTURE_BYTES / 2;
/// Tail budget for command tools that need both the beginning and end of output.
pub const CHILD_PIPE_CAPTURE_TAIL_BYTES: usize =
    CHILD_PIPE_CAPTURE_BYTES - CHILD_PIPE_CAPTURE_HEAD_BYTES;

const PIPE_DRAIN_CHUNK_BYTES: usize = 8 * 1024;

const PINNED_SPAWN_QUEUE_CAPACITY: usize = 64;

enum PinnedSpawnRequest {
    Tokio {
        command: tokio::process::Command,
        runtime: tokio::runtime::Handle,
        response: mpsc::SyncSender<std::io::Result<tokio::process::Child>>,
    },
    Std {
        command: std::process::Command,
        response: mpsc::SyncSender<std::io::Result<std::process::Child>>,
    },
}

static PINNED_SPAWNER: OnceLock<mpsc::SyncSender<PinnedSpawnRequest>> = OnceLock::new();

/// A Linux validation workload owned by a dedicated subreaper process.
///
/// The daemon never becomes a subreaper and never waits for workload PIDs.
/// Closing the control file asks the supervisor to kill and reap its process
/// group; the owner thread waits only for the exact supervisor PID.
#[cfg(target_os = "linux")]
pub struct ValidationSupervisor {
    control: Option<std::fs::File>,
    completion: Arc<ValidationSupervisorCompletion>,
    finished: bool,
}

#[cfg(target_os = "linux")]
struct ValidationSupervisorCompletion {
    result: Mutex<Option<std::io::Result<std::process::ExitStatus>>>,
    ready: std::sync::Condvar,
    notify: tokio::sync::Notify,
}

#[cfg(target_os = "linux")]
impl ValidationSupervisor {
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        loop {
            let notified = self.completion.notify.notified();
            if let Some(result) = self
                .completion
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                self.control.take();
                self.finished = true;
                return result;
            }
            notified.await;
        }
    }

    /// Close the supervisor control channel and synchronously await its exact
    /// status. This is suitable for a destructor that must prove quiescence
    /// before later destructors restore files or release locks.
    pub fn terminate_and_wait(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<std::process::ExitStatus> {
        if self.finished {
            return Err(std::io::Error::other(
                "validation supervisor completion was already consumed",
            ));
        }
        self.control.take();
        let mut result = self
            .completion
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let deadline = Instant::now() + timeout;
        while result.is_none() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "validation supervisor teardown deadline elapsed",
                ));
            };
            let (next, wait) = self
                .completion
                .ready
                .wait_timeout(result, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            result = next;
            if wait.timed_out() && result.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "validation supervisor teardown deadline elapsed",
                ));
            }
        }
        self.finished = true;
        result.take().expect("completion checked")
    }
}

#[cfg(target_os = "linux")]
impl Drop for ValidationSupervisor {
    fn drop(&mut self) {
        if !self.finished {
            self.control.take();
            eprintln!("fatal: validation supervisor dropped without proven workload quiescence");
            std::process::abort();
        }
    }
}

/// Spawn a validation command behind a process-local Linux subreaper.
#[cfg(target_os = "linux")]
pub fn spawn_validation_supervisor(
    program: &std::ffi::OsStr,
    args: &[&str],
    cwd: &std::path::Path,
    env: &[(&str, &std::ffi::OsStr)],
) -> std::io::Result<ValidationSupervisor> {
    use std::ffi::{CString, OsString};
    use std::os::fd::FromRawFd as _;

    fn cstring(bytes: &[u8]) -> std::io::Result<CString> {
        CString::new(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "process argument contains NUL",
            )
        })
    }

    let resolved = resolve_linux_program(program, cwd)?;
    let program = cstring(resolved.as_os_str().as_bytes())?;
    let cwd = cstring(cwd.as_os_str().as_bytes())?;
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(program.clone());
    for arg in args {
        argv.push(cstring(arg.as_bytes())?);
    }
    let mut environment: std::collections::BTreeMap<OsString, OsString> =
        std::env::vars_os().collect();
    for (key, value) in env {
        environment.insert(OsString::from(key), (*value).to_os_string());
    }
    let environment = environment
        .into_iter()
        .map(|(key, value)| {
            let mut bytes = key.as_os_str().as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_os_str().as_bytes());
            cstring(&bytes)
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let completion = Arc::new(ValidationSupervisorCompletion {
        result: Mutex::new(None),
        ready: std::sync::Condvar::new(),
        notify: tokio::sync::Notify::new(),
    });
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let thread_completion = completion.clone();
    std::thread::Builder::new()
        .name("cockpit-validation-supervisor-owner".into())
        .spawn(move || {
            let spawned =
                unsafe { spawn_linux_validation_supervisor(&program, &argv, &cwd, &environment) };
            let (supervisor_pid, control_fd, report_fd) = match spawned {
                Ok(value) => value,
                Err(error) => {
                    let _ = started_tx.send(Err(error));
                    return;
                }
            };
            let control = unsafe { std::fs::File::from_raw_fd(control_fd) };
            if let Err(error) = started_tx.send(Ok(control)) {
                drop(error.0);
            }
            let result = wait_linux_validation_supervisor(supervisor_pid, report_fd);
            *thread_completion
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
            thread_completion.ready.notify_all();
            thread_completion.notify.notify_waiters();
        })?;
    let control = started_rx
        .recv()
        .map_err(|_| std::io::Error::other("validation supervisor owner stopped"))??;
    Ok(ValidationSupervisor {
        control: Some(control),
        completion,
        finished: false,
    })
}

#[cfg(target_os = "linux")]
fn resolve_linux_program(
    program: &std::ffi::OsStr,
    cwd: &std::path::Path,
) -> std::io::Result<std::path::PathBuf> {
    let path = std::path::Path::new(program);
    if path.components().count() > 1 {
        return Ok(if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        });
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(path);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("executable `{}` not found", path.display()),
    ))
}

#[cfg(target_os = "linux")]
unsafe fn spawn_linux_validation_supervisor(
    program: &std::ffi::CStr,
    argv: &[std::ffi::CString],
    cwd: &std::ffi::CStr,
    environment: &[std::ffi::CString],
) -> std::io::Result<(libc::pid_t, libc::c_int, libc::c_int)> {
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|value| value.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> =
        environment.iter().map(|value| value.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    let mut control = [-1; 2];
    let mut startup = [-1; 2];
    let mut report = [-1; 2];
    if unsafe { libc::pipe2(control.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::pipe2(startup.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(control[0]);
            libc::close(control[1]);
        }
        return Err(error);
    }
    if unsafe { libc::pipe2(report.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(control[0]);
            libc::close(control[1]);
            libc::close(startup[0]);
            libc::close(startup[1]);
        }
        return Err(error);
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        let error = std::io::Error::last_os_error();
        for pipe in [&control, &startup, &report] {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
        }
        return Err(error);
    }
    if pid == 0 {
        unsafe {
            libc::close(control[1]);
            libc::close(startup[0]);
            libc::close(report[0]);
            linux_validation_supervisor_main(
                control[0],
                startup[1],
                report[1],
                program,
                argv,
                cwd,
                environment,
                argv_ptrs.as_ptr(),
                env_ptrs.as_ptr(),
            );
        }
    }
    unsafe {
        libc::close(control[0]);
        libc::close(startup[1]);
        libc::close(report[1]);
    }
    let mut exec_errno: libc::c_int = 0;
    let read = unsafe {
        libc::read(
            startup[0],
            (&mut exec_errno as *mut libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>(),
        )
    };
    unsafe { libc::close(startup[0]) };
    if read == std::mem::size_of::<libc::c_int>() as isize && exec_errno != 0 {
        unsafe {
            libc::close(control[1]);
            libc::close(report[0]);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err(std::io::Error::from_raw_os_error(exec_errno));
    }
    if read != 0 {
        unsafe {
            libc::close(control[1]);
            libc::close(report[0]);
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err(std::io::Error::other(
            "validation supervisor startup protocol failed",
        ));
    }
    Ok((pid, control[1], report[0]))
}

/// Runs after fork on the dedicated owner thread. Only libc/syscall-facing
/// operations are permitted before the workload's exec.
#[cfg(target_os = "linux")]
unsafe fn linux_validation_supervisor_main(
    control_fd: libc::c_int,
    startup_fd: libc::c_int,
    report_fd: libc::c_int,
    program: &std::ffi::CStr,
    _argv: &[std::ffi::CString],
    cwd: &std::ffi::CStr,
    _environment: &[std::ffi::CString],
    argv_ptrs: *const *const libc::c_char,
    env_ptrs: *const *const libc::c_char,
) -> ! {
    unsafe {
        if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) != 0 {
            supervisor_startup_error(startup_fd);
        }
        let owner_pid = libc::getppid();
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 || libc::getppid() != owner_pid {
            supervisor_startup_error(startup_fd);
        }
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGCHLD);
        libc::sigaddset(&mut mask, libc::SIGTERM);
        let mut child_action: libc::sigaction = std::mem::zeroed();
        let mut prior_child_action: libc::sigaction = std::mem::zeroed();
        child_action.sa_sigaction = libc::SIG_DFL;
        child_action.sa_flags = libc::SA_NOCLDSTOP;
        libc::sigemptyset(&mut child_action.sa_mask);
        if libc::sigaction(libc::SIGCHLD, &child_action, &mut prior_child_action) != 0 {
            supervisor_startup_error(startup_fd);
        }
        let mut prior_mask: libc::sigset_t = std::mem::zeroed();
        if libc::sigprocmask(libc::SIG_BLOCK, &mask, &mut prior_mask) != 0 {
            supervisor_startup_error(startup_fd);
        }
        let signal_fd = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC);
        if signal_fd < 0 {
            supervisor_startup_error(startup_fd);
        }
        let mut exec_error = [-1; 2];
        if libc::pipe2(exec_error.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            supervisor_startup_error(startup_fd);
        }
        let workload = libc::fork();
        if workload < 0 {
            supervisor_startup_error(startup_fd);
        }
        if workload == 0 {
            libc::close(exec_error[0]);
            libc::sigprocmask(libc::SIG_SETMASK, &prior_mask, std::ptr::null_mut());
            libc::sigaction(libc::SIGCHLD, &prior_child_action, std::ptr::null_mut());
            let supervisor_pid = libc::getppid();
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() != supervisor_pid
                || libc::setpgid(0, 0) != 0
                || libc::chdir(cwd.as_ptr()) != 0
            {
                let errno = *libc::__errno_location();
                libc::write(
                    exec_error[1],
                    (&errno as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>(),
                );
                libc::_exit(127);
            }
            let null_fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            if null_fd < 0 {
                let errno = *libc::__errno_location();
                libc::write(
                    exec_error[1],
                    (&errno as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>(),
                );
                libc::_exit(127);
            }
            libc::dup2(null_fd, libc::STDIN_FILENO);
            libc::dup2(null_fd, libc::STDOUT_FILENO);
            libc::dup2(null_fd, libc::STDERR_FILENO);
            if null_fd > libc::STDERR_FILENO {
                libc::close(null_fd);
            }
            libc::execve(program.as_ptr(), argv_ptrs, env_ptrs);
            let errno = *libc::__errno_location();
            libc::write(
                exec_error[1],
                (&errno as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>(),
            );
            libc::_exit(127);
        }
        libc::close(exec_error[1]);
        let mut exec_errno = 0;
        let exec_read = libc::read(
            exec_error[0],
            (&mut exec_errno as *mut libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>(),
        );
        libc::close(exec_error[0]);
        if exec_read != 0 {
            libc::write(
                startup_fd,
                (&exec_errno as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>(),
            );
            libc::close(startup_fd);
            libc::waitpid(workload, std::ptr::null_mut(), 0);
            libc::_exit(125);
        }
        libc::close(startup_fd);
        close_linux_fds_except(control_fd, report_fd, signal_fd);

        let mut leader_status = 0;
        loop {
            let mut poll_fds = [
                libc::pollfd {
                    fd: control_fd,
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: signal_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            if libc::poll(poll_fds.as_mut_ptr(), 2, -1) < 0
                && *libc::__errno_location() == libc::EINTR
            {
                continue;
            }
            let control_closed = poll_fds[0].revents != 0;
            if poll_fds[1].revents != 0 {
                let mut info: libc::signalfd_siginfo = std::mem::zeroed();
                let _ = libc::read(
                    signal_fd,
                    (&mut info as *mut libc::signalfd_siginfo).cast(),
                    std::mem::size_of::<libc::signalfd_siginfo>(),
                );
            }
            if control_closed {
                libc::kill(-workload, libc::SIGKILL);
                let mut waited;
                loop {
                    waited = libc::waitpid(workload, &mut leader_status, 0);
                    if waited >= 0 || *libc::__errno_location() != libc::EINTR {
                        break;
                    }
                }
                if waited != workload {
                    libc::_exit(125);
                }
                if !reap_all_linux_supervisor_children() {
                    libc::_exit(125);
                }
                libc::write(
                    report_fd,
                    (&leader_status as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>(),
                );
                libc::close(report_fd);
                libc::_exit(0);
            }
            if poll_fds[1].revents != 0 {
                match linux_exact_child_exited(workload) {
                    0 => {
                        // SIGCHLD also reports adopted descendants. Reap only
                        // exact exited children owned by this subreaper, never
                        // infer that the still-live workload leader exited.
                        if !reap_exited_linux_supervisor_children(workload) {
                            libc::_exit(125);
                        }
                    }
                    1 => {
                        // Preserve the leader's natural status. WNOWAIT pins
                        // its PID/group identity until the group signal below.
                        libc::kill(-workload, libc::SIGKILL);
                        let mut waited;
                        loop {
                            waited = libc::waitpid(workload, &mut leader_status, 0);
                            if waited >= 0 || *libc::__errno_location() != libc::EINTR {
                                break;
                            }
                        }
                        if waited != workload || !reap_all_linux_supervisor_children() {
                            libc::_exit(125);
                        }
                        libc::write(
                            report_fd,
                            (&leader_status as *const libc::c_int).cast(),
                            std::mem::size_of::<libc::c_int>(),
                        );
                        libc::close(report_fd);
                        libc::_exit(0);
                    }
                    _ => libc::_exit(125),
                }
            }
        }
    }
}

/// Observe the exact workload leader without consuming its status.
/// Returns 1 for exited, 0 for live, and -1 for an observation failure.
#[cfg(target_os = "linux")]
unsafe fn linux_exact_child_exited(pid: libc::pid_t) -> libc::c_int {
    unsafe {
        loop {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            if libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ) == 0
            {
                return libc::c_int::from(info.si_pid() != 0);
            }
            if *libc::__errno_location() != libc::EINTR {
                return -1;
            }
        }
    }
}

/// Reap exited adopted children while leaving the exact workload leader
/// untouched. Repeating discovers grandchildren adopted when a parent reap
/// changes their parentage.
#[cfg(target_os = "linux")]
unsafe fn reap_exited_linux_supervisor_children(workload: libc::pid_t) -> bool {
    unsafe {
        loop {
            let fd = libc::open(
                c"/proc/thread-self/children".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                return false;
            }
            let mut bytes = [0_u8; 64 * 1024];
            let count = libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len());
            libc::close(fd);
            if count < 0 || count as usize == bytes.len() {
                return false;
            }
            let mut reaped = false;
            let mut pid = 0_i32;
            let mut in_pid = false;
            for byte in bytes[..count as usize]
                .iter()
                .copied()
                .chain(std::iter::once(b' '))
            {
                if byte.is_ascii_digit() {
                    in_pid = true;
                    let Some(next) = pid
                        .checked_mul(10)
                        .and_then(|value| value.checked_add(i32::from(byte - b'0')))
                    else {
                        return false;
                    };
                    pid = next;
                } else if in_pid {
                    if pid != workload {
                        loop {
                            let waited = libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
                            if waited == pid {
                                reaped = true;
                                break;
                            }
                            if waited == 0 {
                                break;
                            }
                            if waited < 0 && *libc::__errno_location() == libc::EINTR {
                                continue;
                            }
                            return false;
                        }
                    }
                    pid = 0;
                    in_pid = false;
                } else if !byte.is_ascii_whitespace() {
                    return false;
                }
            }
            if !reaped {
                return true;
            }
        }
    }
}

/// Kill and reap every exact child adopted by the dedicated supervisor.
/// `/proc/thread-self/children` is an ownership inventory, not a global PID
/// scan; exact `waitpid(pid)` calls therefore cannot consume another owner's
/// status. Repeating handles deeper descendants as each killed parent is
/// reaped and its children are adopted by the subreaper.
#[cfg(target_os = "linux")]
unsafe fn reap_all_linux_supervisor_children() -> bool {
    unsafe {
        loop {
            let fd = libc::open(
                c"/proc/thread-self/children".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            );
            if fd < 0 {
                return false;
            }
            let mut bytes = [0_u8; 64 * 1024];
            let count = libc::read(fd, bytes.as_mut_ptr().cast(), bytes.len());
            libc::close(fd);
            if count < 0 || count as usize == bytes.len() {
                return false;
            }
            let bytes = &bytes[..count as usize];
            let mut found = false;
            let mut pid = 0_i32;
            let mut in_pid = false;
            for byte in bytes.iter().copied().chain(std::iter::once(b' ')) {
                if byte.is_ascii_digit() {
                    in_pid = true;
                    let Some(next) = pid
                        .checked_mul(10)
                        .and_then(|value| value.checked_add(i32::from(byte - b'0')))
                    else {
                        return false;
                    };
                    pid = next;
                } else if in_pid {
                    found = true;
                    libc::kill(pid, libc::SIGKILL);
                    loop {
                        let waited = libc::waitpid(pid, std::ptr::null_mut(), 0);
                        if waited == pid {
                            break;
                        }
                        if waited < 0 && *libc::__errno_location() == libc::EINTR {
                            continue;
                        }
                        return false;
                    }
                    pid = 0;
                    in_pid = false;
                } else if !byte.is_ascii_whitespace() {
                    return false;
                }
            }
            if !found {
                return true;
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn close_linux_fds_except(
    first_keep: libc::c_int,
    second_keep: libc::c_int,
    third_keep: libc::c_int,
) {
    unsafe {
        let mut keep = [first_keep, second_keep, third_keep];
        keep.sort_unstable();
        let mut first = 3_u32;
        let mut close_range_supported = true;
        for kept in keep {
            let Ok(kept) = u32::try_from(kept) else {
                continue;
            };
            if first < kept && libc::syscall(libc::SYS_close_range, first, kept - 1, 0) != 0 {
                close_range_supported = false;
                break;
            }
            first = kept.saturating_add(1);
        }
        if close_range_supported {
            let _ = libc::syscall(libc::SYS_close_range, first, u32::MAX, 0);
            return;
        }
        let mut limit: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return;
        }
        let upper = limit.rlim_cur.min(i32::MAX as libc::rlim_t) as libc::c_int;
        for fd in 3..upper {
            if !keep.contains(&fd) {
                libc::close(fd);
            }
        }
    }
}

#[cfg(target_os = "linux")]
unsafe fn supervisor_startup_error(startup_fd: libc::c_int) -> ! {
    unsafe {
        let errno = *libc::__errno_location();
        libc::write(
            startup_fd,
            (&errno as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>(),
        );
        libc::_exit(125);
    }
}

#[cfg(target_os = "linux")]
fn wait_linux_validation_supervisor(
    pid: libc::pid_t,
    report_fd: libc::c_int,
) -> std::io::Result<std::process::ExitStatus> {
    let mut workload_status = 0;
    let read = unsafe {
        libc::read(
            report_fd,
            (&mut workload_status as *mut libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>(),
        )
    };
    unsafe { libc::close(report_fd) };
    let mut supervisor_status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut supervisor_status, 0) };
        if waited == pid {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
    if read != std::mem::size_of::<libc::c_int>() as isize
        || !std::process::ExitStatus::from_raw(supervisor_status).success()
    {
        return Err(std::io::Error::other(
            "validation supervisor failed before proving workload quiescence",
        ));
    }
    Ok(std::process::ExitStatus::from_raw(workload_status))
}

/// Start the process-wide child spawner on one dedicated, long-lived OS
/// thread. Linux parent-death signals are bound to the thread that calls
/// `fork`, so routing every protected spawn through this thread makes the
/// parent identity stable for the daemon's entire lifetime.
pub fn start_pinned_spawner() -> std::io::Result<()> {
    if PINNED_SPAWNER.get().is_some() {
        return Ok(());
    }
    let (sender, receiver) = mpsc::sync_channel::<PinnedSpawnRequest>(PINNED_SPAWN_QUEUE_CAPACITY);
    std::thread::Builder::new()
        .name("cockpit-process-spawner".into())
        .spawn(move || {
            while let Ok(request) = receiver.recv() {
                match request {
                    PinnedSpawnRequest::Tokio {
                        mut command,
                        runtime,
                        response,
                    } => {
                        let _runtime = runtime.enter();
                        let _ = response.send(command.spawn());
                    }
                    PinnedSpawnRequest::Std {
                        mut command,
                        response,
                    } => {
                        let _ = response.send(command.spawn());
                    }
                }
            }
        })?;
    // Another caller can win only in a unit-test race. Its identical worker
    // exits when this sender is dropped; all production calls use the winner.
    let _ = PINNED_SPAWNER.set(sender);
    Ok(())
}

/// Spawn a protected Tokio child from the dedicated process spawner.
///
/// On Linux the direct child is armed with `PDEATHSIG(SIGKILL)` before exec,
/// then rechecks that its parent is still the daemon process recorded before
/// the request crossed the channel. The recheck closes the fork/prctl race.
pub fn spawn_pinned(
    mut command: tokio::process::Command,
) -> std::io::Result<tokio::process::Child> {
    start_pinned_spawner()?;
    arm_parent_death(command.as_std_mut());
    let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
        std::io::Error::other(format!("protected spawn requires a Tokio runtime: {error}"))
    })?;
    let (response, result) = mpsc::sync_channel(1);
    PINNED_SPAWNER
        .get()
        .expect("pinned spawner initialized")
        .send(PinnedSpawnRequest::Tokio {
            command,
            runtime,
            response,
        })
        .map_err(|_| std::io::Error::other("protected process spawner stopped"))?;
    result
        .recv()
        .map_err(|_| std::io::Error::other("protected process spawner dropped its response"))?
}

/// Synchronous-command counterpart to [`spawn_pinned`]. This is used by
/// blocking host probes and capture helpers that still require the same
/// daemon-crash containment contract.
pub fn spawn_std_pinned(
    mut command: std::process::Command,
) -> std::io::Result<std::process::Child> {
    start_pinned_spawner()?;
    arm_parent_death(&mut command);
    let (response, result) = mpsc::sync_channel(1);
    PINNED_SPAWNER
        .get()
        .expect("pinned spawner initialized")
        .send(PinnedSpawnRequest::Std { command, response })
        .map_err(|_| std::io::Error::other("protected process spawner stopped"))?;
    result
        .recv()
        .map_err(|_| std::io::Error::other("protected process spawner dropped its response"))?
}

fn arm_parent_death(command: &mut std::process::Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt as _;

        let daemon_pid = unsafe { libc::getpid() };
        // SAFETY: this closure runs after fork and before exec and calls only
        // async-signal-safe libc functions. It neither allocates nor touches
        // locks inherited from the multithreaded daemon.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != daemon_pid {
                    return Err(std::io::Error::from_raw_os_error(libc::ECANCELED));
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = command;
}

/// Unix process-group membership recorded on a [`ProcessTreeGuard`].
///
/// A numeric pgid is a recycled-identity hazard the moment the original
/// group can empty. Signal authority requires a parent-owned attribution
/// proof: the unreaped leader pin (`waitid` `WNOWAIT`) *and* the kernel
/// process-start identity captured at [`ProcessTreeGuard::assign`]. `waitid`
/// alone is pid-parenthood (any unreaped child of this process at that
/// number); the start identity is guard-child sameness. An unattributable
/// membership (spawned child, never bound, or pin lost without a successful
/// SIGKILL) must never be treated as empty and must never be a signal target.
///
/// The pin is proven at check time, immediately before `kill(-pgid)`, under
/// this guard's mutex. Reaping is outside that mutex: callers must not reap
/// the assigned leader concurrently with [`ProcessTreeGuard::terminate`]
/// (see that method's contract).
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnixGroup {
    /// No child has been assigned. The empty oracle is empty.
    Unbound,
    /// Leader assigned. `signaled` is true after `terminate` has sent
    /// SIGKILL once (Ok or ESRCH); further `terminate` calls must not
    /// re-signal. A failed signal leaves `signaled` false so a later
    /// attempt may retry only while the unreaped leader pin holds. Losing
    /// that pin without a successful signal forgets this identity.
    Bound {
        pgid: libc::pid_t,
        start: crate::daemon_lifecycle::ProcessStartIdentity,
        signaled: bool,
    },
    /// A child ran (or assign failed after spawn) but this guard does not
    /// hold an attributable pgid. Never empty; never a signal target.
    /// Terminal for this guard: [`ProcessTreeGuard::assign`] must not re-bind
    /// a later child, or a subsequent Empty would fabricate ProvenEmpty for
    /// the unobserved earlier membership.
    Unattributable,
}

/// Result of the Unix empty oracle, including membership that cannot be
/// attributed to this guard.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupPopulation {
    Empty,
    Populated,
    Unattributable,
}

/// Stable reason when Unix membership cannot be attributed to this lease.
#[cfg(unix)]
pub const PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE: &str = "process_group_membership_unattributable";

/// A descendant-containment boundary prepared before spawn and attached
/// before child code is allowed to execute. Unix uses a fresh process group.
/// Windows uses a pre-created kill-on-close Job Object and a suspended child,
/// then assigns the process before resuming its primary thread. Other targets
/// fail closed instead of pretending a direct-child kill contains descendants.
pub struct ProcessTreeGuard {
    #[cfg(unix)]
    group: Mutex<UnixGroup>,
    #[cfg(windows)]
    job: Mutex<Option<windows_sys::Win32::Foundation::HANDLE>>,
}

// The Job Object handle is an owned kernel handle. Its operations are
// thread-safe, and this type never exposes or aliases the raw handle.
#[cfg(windows)]
unsafe impl Send for ProcessTreeGuard {}
#[cfg(windows)]
unsafe impl Sync for ProcessTreeGuard {}

impl ProcessTreeGuard {
    /// Create the containment object without spawning or resuming user code.
    pub fn allocate() -> anyhow::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                group: Mutex::new(UnixGroup::Unbound),
            })
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::JobObjects::{
                CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            };

            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let configured = unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    u32::try_from(std::mem::size_of_val(&limits)).unwrap_or(u32::MAX),
                )
            };
            if configured == 0 {
                unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(Self {
                job: Mutex::new(Some(job)),
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            anyhow::bail!("descendant_process_containment_unavailable")
        }
    }

    /// Apply spawn flags so the next child can join this guard. Never starts
    /// user instructions: Windows uses `CREATE_SUSPENDED`, Unix a fresh group.
    ///
    /// Linux parent-death containment is installed by [`spawn_pinned`], which
    /// performs the actual fork from the daemon's stable spawner thread.
    pub fn apply_spawn_flags(&self, command: &mut tokio::process::Command) {
        let _ = self;
        #[cfg(unix)]
        {
            command.process_group(0);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            command
                .as_std_mut()
                .creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED);
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = command;
        }
    }

    pub fn prepare(command: &mut tokio::process::Command) -> anyhow::Result<Self> {
        let guard = Self::allocate()?;
        guard.apply_spawn_flags(command);
        Ok(guard)
    }

    /// Whether this process is already a member of any Job Object.
    ///
    /// Nested-job hosts (CI, terminal launchers, nested Cockpit) force
    /// Unsupported at the Windows adapter: assignment may succeed via nesting
    /// while outer-job limits still apply. Probe failure is fail-closed.
    #[cfg(windows)]
    pub fn current_process_is_in_job() -> std::io::Result<bool> {
        use windows_sys::Win32::System::{
            JobObjects::IsProcessInJob, Threading::GetCurrentProcess,
        };

        let mut in_job: windows_sys::core::BOOL = 0;
        // A null job handle means "any job".
        if unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(in_job != 0)
    }

    /// Assign `child` to this containment object. Does not resume user code.
    ///
    /// On Unix this records the child's pgid together with its kernel
    /// process-start identity. That pair is the only attribution proof a
    /// later [`terminate`](Self::terminate) may signal. The child must still
    /// be this process's unreaped leader: callers must not reap `child`
    /// concurrently with `terminate` / `Drop`, and must not spawn a
    /// replacement own-group child at the same pid until `terminate` has
    /// returned. [`wait_for_exit_without_reaping`] is the observe-then-
    /// terminate-then-reap protocol that keeps the pin held.
    ///
    /// Only an unbound guard may bind. Bound and unattributable membership
    /// are terminal for this guard: a second `assign` must not replace them,
    /// or a later empty probe would fabricate ProvenEmpty for an unobserved
    /// earlier membership.
    pub fn assign(&self, child: &tokio::process::Child) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            let mut group = self
                .group
                .lock()
                .map_err(|_| anyhow::anyhow!("process tree group lock poisoned"))?;
            match *group {
                UnixGroup::Bound { .. } => {
                    return Err(anyhow::anyhow!("process group already bound"));
                }
                UnixGroup::Unattributable => {
                    return Err(anyhow::anyhow!(PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE));
                }
                UnixGroup::Unbound => {}
            }
            let result = (|| -> anyhow::Result<(libc::pid_t, crate::daemon_lifecycle::ProcessStartIdentity)> {
                let pid = child
                    .id()
                    .ok_or_else(|| anyhow::anyhow!("child identity missing"))?;
                let pid = libc::pid_t::try_from(pid)
                    .map_err(|_| anyhow::anyhow!("child pid is not a valid process-group id"))?;
                // SAFETY: `pid` is the child we just spawned and have not reaped;
                // `getpgid` only queries the kernel process-group identity.
                let pgid = unsafe { libc::getpgid(pid) };
                if pgid < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                if pgid != pid {
                    return Err(anyhow::anyhow!(
                        "child is not the leader of its process group"
                    ));
                }
                let start = crate::daemon_lifecycle::process_start_identity(pid as u32)
                    .map_err(|e| anyhow::anyhow!("child start identity missing: {e}"))?;
                Ok((pgid, start))
            })();
            match result {
                Ok((pgid, start)) => {
                    *group = UnixGroup::Bound {
                        pgid,
                        start,
                        signaled: false,
                    };
                    Ok(())
                }
                Err(error) => {
                    // A child existed (or was claimed to) but membership did not
                    // bind. Unbound-empty would fabricate ProvenEmpty for a
                    // lease that ran user code.
                    *group = UnixGroup::Unattributable;
                    Err(error)
                }
            }
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::JobObjects::{
                AssignProcessToJobObject, IsProcessInJob,
            };

            let process = child
                .raw_handle()
                .ok_or_else(|| anyhow::anyhow!("child process handle missing"))?
                as windows_sys::Win32::Foundation::HANDLE;
            let job = self
                .job
                .lock()
                .map_err(|_| anyhow::anyhow!("process tree job lock poisoned"))?
                .ok_or_else(|| anyhow::anyhow!("process tree job already closed"))?;
            if unsafe { AssignProcessToJobObject(job, process) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // Membership is proven before ResumeThread so no user instruction
            // runs outside the job.
            let mut in_job: windows_sys::core::BOOL = 0;
            if unsafe { IsProcessInJob(process, job, &mut in_job) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if in_job == 0 {
                return Err(anyhow::anyhow!("child not a member of the job object"));
            }
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            anyhow::bail!("descendant_process_containment_unavailable")
        }
    }

    /// Resume user instructions after membership is proven and the caller has
    /// armed drop-safety / write-scope release.
    pub fn resume(&self, child: &tokio::process::Child) -> anyhow::Result<()> {
        let _ = self;
        #[cfg(unix)]
        {
            // Unix has no CREATE_SUSPENDED equivalent that `Command::spawn`
            // can return from: `process_group(0)` already placed the child in
            // a fresh group before exec. Resume is a no-op.
            let _ = child;
            return Ok(());
        }
        #[cfg(windows)]
        {
            use windows_sys::Win32::{
                Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
                System::{
                    Diagnostics::ToolHelp::{
                        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                        Thread32Next,
                    },
                    Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME},
                },
            };

            let pid = child
                .id()
                .ok_or_else(|| anyhow::anyhow!("child identity missing"))?;
            let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
            if snapshot == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error().into());
            }
            let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
            entry.dwSize = u32::try_from(std::mem::size_of::<THREADENTRY32>()).unwrap_or(u32::MAX);
            let mut found = None;
            let mut more = unsafe { Thread32First(snapshot, &mut entry) } != 0;
            while more {
                if entry.th32OwnerProcessID == pid {
                    found = Some(entry.th32ThreadID);
                    break;
                }
                more = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
            }
            unsafe { CloseHandle(snapshot) };
            let thread_id = found.ok_or_else(|| anyhow::anyhow!("child thread missing"))?;
            let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) };
            if thread.is_null() {
                return Err(std::io::Error::last_os_error().into());
            }
            let resumed = unsafe { ResumeThread(thread) };
            unsafe { CloseHandle(thread) };
            if resumed == u32::MAX {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = child;
            anyhow::bail!("descendant_process_containment_unavailable")
        }
    }

    /// Assign then resume. Callers that have already armed drop-safety and do
    /// not need a delayed-release window (for example media tools) use this.
    pub fn attach(&self, child: &tokio::process::Child) -> anyhow::Result<()> {
        self.assign(child)?;
        self.resume(child)
    }

    /// Kill every process in this containment.
    ///
    /// Unix: `kill(-pgid, SIGKILL)` only while the unreaped-leader pin holds
    /// for the *assigned* child (waitid parenthood plus the start identity
    /// recorded by [`assign`](Self::assign)). The pin is checked and the
    /// signal is sent under this guard's mutex; the caller's reaper is not.
    /// Callers must not reap the assigned leader concurrently with this
    /// method (or `Drop`), and must not spawn a replacement own-group child
    /// at the same pid until it returns. The sanctioned order is
    /// [`wait_for_exit_without_reaping`] → `terminate` → `child.wait()`.
    ///
    /// Ok/ESRCH consume the one-shot so a later retry cannot target a
    /// recycle; the bound identity is kept so the empty oracle can still
    /// observe ESRCH after the leader is reaped. A failed signal (EPERM)
    /// leaves the one-shot open so a later attempt may retry while that pin
    /// holds. Losing the pin without a successful signal forgets the pgid:
    /// Drop/retry must not send `kill(-pgid)`.
    pub fn terminate(&self) -> anyhow::Result<()> {
        #[cfg(unix)]
        {
            let mut group = self
                .group
                .lock()
                .map_err(|_| anyhow::anyhow!("process tree group lock poisoned"))?;
            forget_unpinned_signal_target(&mut group);
            match *group {
                UnixGroup::Bound {
                    pgid,
                    start,
                    signaled: false,
                } => {
                    match signal_pinned_group(pgid, start, libc::SIGKILL) {
                        Ok(()) => {}
                        Err(error) if is_esrch(&error) => {}
                        Err(error) => return Err(error.into()),
                    }
                    *group = UnixGroup::Bound {
                        pgid,
                        start,
                        signaled: true,
                    };
                }
                UnixGroup::Bound { signaled: true, .. }
                | UnixGroup::Unbound
                | UnixGroup::Unattributable => {}
            }
        }
        #[cfg(windows)]
        {
            let job = self
                .job
                .lock()
                .map_err(|_| anyhow::anyhow!("process tree job lock poisoned"))?
                .ok_or_else(|| anyhow::anyhow!("process tree job already closed"))?;
            if unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(job, 1) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }

    /// Forget the bound Unix process-group identity after the empty oracle
    /// has fired, so Drop cannot signal a recycled pgid. Unattributable
    /// membership is preserved: releasing must not turn a failed bind into
    /// unbound-empty.
    #[cfg(unix)]
    pub fn release_group(&self) {
        let mut group = self
            .group
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !matches!(*group, UnixGroup::Unattributable) {
            *group = UnixGroup::Unbound;
        }
    }

    /// Drop signal/query authority without claiming the group empty. Used
    /// when settlement is Uncertain after SIGKILL or pin-loss: the pgid
    /// must not be retained for a later recycled-identity kill.
    #[cfg(unix)]
    pub fn release_signal_authority(&self) {
        let mut group = self
            .group
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(*group, UnixGroup::Bound { .. }) {
            *group = UnixGroup::Unattributable;
        }
    }

    /// Whether a process-group leader has been assigned to this guard.
    #[cfg(unix)]
    pub fn group_is_bound(&self) -> bool {
        let mut group = self
            .group
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        forget_unpinned_signal_target(&mut group);
        matches!(*group, UnixGroup::Bound { .. })
    }

    /// Whether `terminate` has already sent SIGKILL for the bound identity.
    #[cfg(unix)]
    pub fn group_terminate_signaled(&self) -> bool {
        let mut group = self
            .group
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        forget_unpinned_signal_target(&mut group);
        matches!(*group, UnixGroup::Bound { signaled: true, .. })
    }

    /// Whether membership cannot be attributed (assign failed, pin lost
    /// without a successful signal, or signal authority was dropped
    /// without an empty proof).
    #[cfg(unix)]
    pub fn group_is_unattributable(&self) -> bool {
        let mut group = self
            .group
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        forget_unpinned_signal_target(&mut group);
        matches!(*group, UnixGroup::Unattributable)
    }

    /// Unix empty oracle: `kill(-pgid, 0)` while membership is bound.
    /// Unbound guards are empty. Unattributable membership is not empty.
    /// A bound identity that has not yet been signaled is forgotten if the
    /// leader pin is gone, so the oracle never probes a recycled pgid as a
    /// prelude to a later `kill(-pgid, SIGKILL)`.
    #[cfg(unix)]
    pub fn group_population(&self) -> anyhow::Result<GroupPopulation> {
        let mut group = self
            .group
            .lock()
            .map_err(|_| anyhow::anyhow!("process tree group lock poisoned"))?;
        forget_unpinned_signal_target(&mut group);
        match *group {
            UnixGroup::Unbound => Ok(GroupPopulation::Empty),
            UnixGroup::Unattributable => Ok(GroupPopulation::Unattributable),
            UnixGroup::Bound { pgid, .. } => {
                if group_exists(pgid) {
                    Ok(GroupPopulation::Populated)
                } else {
                    Ok(GroupPopulation::Empty)
                }
            }
        }
    }

    /// Whether the bound process group still has at least one member.
    ///
    /// This is the Unix empty oracle: `kill(-pgid, 0)`, not a local counter,
    /// child-exit wait, or `/proc` poll. Unbound guards are empty.
    /// Unattributable membership returns an error so callers cannot treat
    /// a spawned-but-unbound lease as ProvenEmpty.
    #[cfg(unix)]
    pub fn group_is_populated(&self) -> anyhow::Result<bool> {
        match self.group_population()? {
            GroupPopulation::Empty => Ok(false),
            GroupPopulation::Populated => Ok(true),
            GroupPopulation::Unattributable => {
                anyhow::bail!(PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE)
            }
        }
    }

    /// Close the owned Windows job as the kill-on-close fallback. The handle is
    /// taken exactly once so Drop cannot double-close it.
    #[cfg(windows)]
    pub fn close_job(&self) -> anyhow::Result<()> {
        let job = self
            .job
            .lock()
            .map_err(|_| anyhow::anyhow!("process tree job lock poisoned"))?
            .take();
        if let Some(job) = job
            && unsafe { windows_sys::Win32::Foundation::CloseHandle(job) } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// Whether the owned Job Object handle is still open.
    #[cfg(windows)]
    pub fn job_is_open(&self) -> bool {
        self.job
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }

    /// Kernel-observed active process count for the owned Job Object.
    ///
    /// This is the empty oracle: it is `QueryInformationJobObject` accounting,
    /// not a local counter, child-exit wait, or PID poll.
    #[cfg(windows)]
    pub fn active_process_count(&self) -> anyhow::Result<u32> {
        use windows_sys::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };

        let job = self
            .job
            .lock()
            .map_err(|_| anyhow::anyhow!("process tree job lock poisoned"))?
            .ok_or_else(|| anyhow::anyhow!("process tree job already closed"))?;
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut returned = 0u32;
        let queried = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                u32::try_from(std::mem::size_of_val(&info)).unwrap_or(u32::MAX),
                &mut returned,
            )
        };
        if queried == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(info.ActiveProcesses)
    }
}

/// Wait until a Unix child has exited without reaping it.
///
/// `WNOWAIT` deliberately leaves the group leader as a zombie, pinning its PID
/// and therefore the process-group identity until descendant containment has
/// been applied. This is observation only: it does not authorize `kill(-pgid)`
/// by itself. Pair it with [`ProcessTreeGuard::terminate`] (or a pinned
/// `terminate_group_*` helper) *before* reaping. Callers must not reap the
/// leader concurrently with that terminate, and must not spawn a replacement
/// own-group child at the same pid until terminate has returned. Reap only
/// afterward.
#[cfg(unix)]
pub async fn wait_for_exit_without_reaping(pid: u32) -> std::io::Result<()> {
    let pid = libc::pid_t::try_from(pid)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid child pid"))?;
    loop {
        // `observe_child_exit_without_reaping` keeps `siginfo_t` off this
        // future: on Darwin it carries an `si_addr: *mut c_void`, which would
        // make the future non-Send and break every `#[async_trait]` caller.
        if observe_child_exit_without_reaping(pid)? {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[cfg(unix)]
impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        // `terminate` refuses to signal without a leader pin, so Drop cannot
        // SIGKILL a recycled pgid after the caller has already reaped.
        let _ = self.terminate();
        self.release_group();
    }
}

#[cfg(windows)]
impl Drop for ProcessTreeGuard {
    fn drop(&mut self) {
        let _ = self.close_job();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedPipeCapture {
    pub bytes: Vec<u8>,
    pub dropped_bytes: usize,
    /// Byte length of the retained HEAD within `bytes`: `bytes[..head_len]` is the
    /// head, `bytes[head_len..]` is the tail. `head_len` lands on a char boundary
    /// of the original stream (the drainer snapped the head there), so when
    /// `dropped_bytes > 0` this is exactly the head→omitted-middle→tail junction a
    /// redaction-aware consumer must treat as a boundary. Equals `bytes.len()`
    /// when nothing was pushed to the tail (small output; no junction).
    pub head_len: usize,
}

#[derive(Debug)]
pub struct BoundedPipeDrain {
    task: JoinHandle<()>,
    state: Arc<Mutex<BoundedPipeDrainState>>,
}

impl BoundedPipeDrain {
    pub fn abort(&self) {
        self.task.abort();
    }

    pub fn snapshot(&self) -> BoundedPipeCapture {
        drain_state_snapshot(&self.state)
    }

    pub async fn join(self) -> BoundedPipeCapture {
        let _ = self.task.await;
        drain_state_snapshot(&self.state)
    }

    pub async fn join_lossy(self) -> String {
        String::from_utf8_lossy(&self.join().await.bytes).into_owned()
    }
}

#[derive(Debug)]
struct BoundedPipeDrainState {
    head_bytes: usize,
    tail_bytes: usize,
    head: Vec<u8>,
    tail: Vec<u8>,
    total_read: usize,
}

impl BoundedPipeDrainState {
    fn new(head_bytes: usize, tail_bytes: usize) -> Self {
        Self {
            head_bytes,
            tail_bytes,
            head: Vec::with_capacity(head_bytes.min(PIPE_DRAIN_CHUNK_BYTES)),
            tail: Vec::with_capacity(tail_bytes.min(PIPE_DRAIN_CHUNK_BYTES)),
            total_read: 0,
        }
    }

    fn append(&mut self, bytes: &[u8]) {
        self.total_read = self.total_read.saturating_add(bytes.len());
        let mut remaining = bytes;
        if self.head.len() < self.head_bytes {
            let take = (self.head_bytes - self.head.len()).min(remaining.len());
            self.head.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            if self.head.len() == self.head_bytes {
                let keep = utf8_prefix_boundary(&self.head, self.head.len());
                if keep < self.head.len() {
                    let overflow = self.head.split_off(keep);
                    self.push_tail(&overflow);
                }
            }
        }
        self.push_tail(remaining);
    }

    fn push_tail(&mut self, bytes: &[u8]) {
        if self.tail_bytes == 0 || bytes.is_empty() {
            return;
        }
        self.tail.extend_from_slice(bytes);
        if self.tail.len() > self.tail_bytes {
            let excess = self.tail.len() - self.tail_bytes;
            let cut = utf8_suffix_boundary(&self.tail, excess);
            self.tail.drain(..cut);
        }
    }

    fn snapshot(&self) -> BoundedPipeCapture {
        let mut bytes = Vec::with_capacity(self.head.len() + self.tail.len());
        bytes.extend_from_slice(&self.head);
        bytes.extend_from_slice(&self.tail);
        BoundedPipeCapture {
            dropped_bytes: self.total_read.saturating_sub(bytes.len()),
            head_len: self.head.len(),
            bytes,
        }
    }
}

pub fn spawn_bounded_pipe_drain<R>(
    reader: Option<R>,
    head_bytes: usize,
    tail_bytes: usize,
) -> BoundedPipeDrain
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let state = Arc::new(Mutex::new(BoundedPipeDrainState::new(
        head_bytes, tail_bytes,
    )));
    let task_state = Arc::clone(&state);
    let task = tokio::spawn(async move {
        let Some(mut reader) = reader else {
            return;
        };
        let mut chunk = [0u8; PIPE_DRAIN_CHUNK_BYTES];
        loop {
            match reader.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    lock_drain_state(&task_state).append(&chunk[..n]);
                }
                Err(_) => break,
            }
        }
    });
    BoundedPipeDrain { task, state }
}

fn drain_state_snapshot(state: &Arc<Mutex<BoundedPipeDrainState>>) -> BoundedPipeCapture {
    lock_drain_state(state).snapshot()
}

fn lock_drain_state(
    state: &Arc<Mutex<BoundedPipeDrainState>>,
) -> std::sync::MutexGuard<'_, BoundedPipeDrainState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn utf8_prefix_boundary(buf: &[u8], idx: usize) -> usize {
    let idx = idx.min(buf.len());
    match std::str::from_utf8(&buf[..idx]) {
        Ok(_) => idx,
        Err(error) => error.valid_up_to(),
    }
}

fn utf8_suffix_boundary(buf: &[u8], idx: usize) -> usize {
    let mut i = idx.min(buf.len());
    while i < buf.len() && (buf[i] & 0b1100_0000) == 0b1000_0000 {
        i += 1;
    }
    i
}

#[cfg(unix)]
fn unix_group_signal_target(pgid: i32) -> i32 {
    -pgid
}

#[cfg(all(test, unix))]
thread_local! {
    static TEST_GROUP_SIGNAL_ERRNO: std::cell::Cell<i32> = const { std::cell::Cell::new(0) };
    static TEST_GROUP_SIGNAL_COUNT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[cfg(unix)]
fn signal_group(pgid: i32, sig: libc::c_int) -> std::io::Result<()> {
    #[cfg(test)]
    {
        TEST_GROUP_SIGNAL_COUNT.with(|cell| cell.set(cell.get().saturating_add(1)));
        let errno = TEST_GROUP_SIGNAL_ERRNO.with(|cell| cell.replace(0));
        if errno != 0 {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
    }
    // SAFETY: `libc::kill` with a negative pid signals the process
    // group; passing a valid pgid (== the leader pid, since callers set
    // `process_group(0)`) is sound.
    let rc = unsafe { libc::kill(unix_group_signal_target(pgid), sig) };
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

/// Parent-owned proof that `pid` still names this process's unreaped child.
///
/// `waitid(P_PID, ..., WNOWAIT)` succeeds only for our child; a recycled
/// PID at the same number is `ECHILD`. `Ok(true)` means the child has
/// exited and is still a zombie (pin holds). `Ok(false)` means it is still
/// running (pin holds). `Err` means the identity is no longer ours.
#[cfg(unix)]
fn observe_child_exit_without_reaping(pid: libc::pid_t) -> std::io::Result<bool> {
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: `info` points to writable initialized storage. `P_PID`
        // restricts observation to the exact child identity, and `WNOWAIT`
        // guarantees the observation cannot release that identity for reuse.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        // SAFETY: waitid initialized the SIGCHLD fields in `info`; a zero
        // PID is the specified WNOHANG result when the child has not exited.
        let observed_pid = unsafe { info.si_pid() };
        return Ok(observed_pid != 0);
    }
}

/// Whether `pgid` still names the assigned unreaped leader.
///
/// `waitid(P_PID, ..., WNOWAIT)` is pid-parenthood: it succeeds for *any*
/// unreaped child of this process at that number. The start identity is
/// guard-child sameness: a reaped leader whose pid is immediately recycled
/// by a new own-group child fails this check. Both must hold. Fail closed
/// if the start identity cannot be re-read.
#[cfg(unix)]
fn leader_pin_holds(
    pgid: libc::pid_t,
    start: crate::daemon_lifecycle::ProcessStartIdentity,
) -> bool {
    if observe_child_exit_without_reaping(pgid).is_err() {
        return false;
    }
    match crate::daemon_lifecycle::process_start_identity(pgid as u32) {
        Ok(observed) => observed == start,
        Err(_) => false,
    }
}

/// Capture a leader pin from a live child pid. `None` if this process does
/// not currently hold that unreaped child or its start identity is missing.
#[cfg(unix)]
fn capture_leader_pin(
    pgid: libc::pid_t,
) -> Option<(libc::pid_t, crate::daemon_lifecycle::ProcessStartIdentity)> {
    if pgid <= 0 {
        return None;
    }
    if observe_child_exit_without_reaping(pgid).is_err() {
        return None;
    }
    let start = crate::daemon_lifecycle::process_start_identity(pgid as u32).ok()?;
    Some((pgid, start))
}

/// Signal a process group only while the unreaped assigned-leader pin holds.
#[cfg(unix)]
fn signal_pinned_group(
    pgid: libc::pid_t,
    start: crate::daemon_lifecycle::ProcessStartIdentity,
    sig: libc::c_int,
) -> std::io::Result<()> {
    if !leader_pin_holds(pgid, start) {
        return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
    }
    signal_group(pgid, sig)
}

/// Forget a bound pgid that can no longer be attributed. A successful
/// SIGKILL keeps the identity so the empty oracle can still observe ESRCH
/// after the leader is reaped; an unsignaled identity without a pin must
/// not remain a signal target.
#[cfg(unix)]
fn forget_unpinned_signal_target(group: &mut UnixGroup) {
    match *group {
        UnixGroup::Bound {
            pgid,
            start,
            signaled: false,
        } if !leader_pin_holds(pgid, start) => {
            *group = UnixGroup::Unattributable;
        }
        _ => {}
    }
}

#[cfg(unix)]
fn group_exists(pgid: i32) -> bool {
    // SAFETY: signal 0 performs existence/permission checking only. The
    // negative pid addresses the process group created by `process_group(0)`.
    let rc = unsafe { libc::kill(unix_group_signal_target(pgid), 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Terminate a caller-created Unix process group and reap its leader.
///
/// On non-Unix targets this is only a direct-child compatibility helper. Code
/// that promises descendant containment must prepare and retain a
/// [`ProcessTreeGuard`] and call its `terminate` method before reaping.
pub async fn terminate_group_async(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    grace: Duration,
) {
    let _ = terminate_group_and_reap_status_async(child, pid, grace).await;
}

/// Terminate a caller-created process group and return the reaped leader
/// status. Unix keeps the leader identity unreaped until all group signaling
/// has completed, so a recycled PID can never become a signal target.
pub async fn terminate_group_and_reap_status_async(
    child: &mut tokio::process::Child,
    pid: Option<u32>,
    grace: Duration,
) -> std::io::Result<std::process::ExitStatus> {
    #[cfg(unix)]
    {
        // Tokio clears `Child::id()` after a reap. Never use a separately
        // cached numeric PID once the child no longer proves that identity.
        // `id()` being Some is necessary but not sufficient: also require
        // the unreaped-leader pin (waitid + start identity) before any
        // `kill(-pgid)`.
        let live_pid = pid
            .filter(|pid| child.id() == Some(*pid))
            .and_then(|pid| i32::try_from(pid).ok());
        if let Some((pgid, start)) = live_pid.and_then(capture_leader_pin) {
            match signal_pinned_group(pgid, start, libc::SIGTERM) {
                Ok(()) => {}
                Err(error) if is_esrch(&error) => {
                    return child.wait().await;
                }
                Err(_) => {
                    let _ = child.start_kill();
                    return child.wait().await;
                }
            }
            if !grace.is_zero() {
                tokio::select! {
                    status = child.wait() => return status,
                    _ = tokio::time::sleep(grace) => {}
                }
            }
            if leader_pin_holds(pgid, start) && group_exists(pgid) {
                let _ = signal_pinned_group(pgid, start, libc::SIGKILL);
            }
        } else {
            let _ = child.kill().await;
        }
        child.wait().await
    }
    #[cfg(not(unix))]
    {
        let _ = grace;
        let _ = pid;
        let _ = child.kill().await;
        child.wait().await
    }
}

/// SIGTERM a Unix process group whose leader pid is `pgid` (spawned with
/// `process_group(0)`). Does not reap and does not require a live `Child`,
/// so a handle can group-kill after the runner task has been aborted.
/// No-op on non-Unix targets (no process groups).
pub fn terminate_process_group(pgid: u32) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(pgid) {
            let _ = signal_group(pid, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pgid;
    }
}

/// SIGKILL a Unix process group whose leader pid is `pgid`. Does not reap.
/// No-op on non-Unix targets.
pub fn kill_process_group(pgid: u32) {
    #[cfg(unix)]
    {
        if let Ok(pid) = i32::try_from(pgid) {
            let _ = signal_group(pid, libc::SIGKILL);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pgid;
    }
}

/// Begin terminating a Tokio child and, on Unix, every process in the child
/// process group. This is the non-async counterpart used from `Drop` paths
/// that can finish cleanup later; callers that can await should use
/// [`terminate_group_async`] so a stubborn group also receives SIGKILL after
/// its grace period. Callers whose later `Drop` impls restore files or
/// release locks must use [`terminate_group_kill_wait`] instead so
/// descendants cannot keep mutating after this returns.
pub fn terminate_group_start(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    {
        if let Some((pgid, start)) = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(capture_leader_pin)
        {
            match signal_pinned_group(pgid, start, libc::SIGTERM) {
                Ok(()) => return,
                Err(error) if is_esrch(&error) => return,
                Err(_) => {}
            }
        }
    }
    let _ = child.start_kill();
}

/// SIGKILL a Tokio child and, on Unix, every process in its process group,
/// then block until the group is gone or `timeout` elapses.
///
/// Drop cannot await [`terminate_group_async`]'s SIGTERM grace, and
/// [`terminate_group_start`] returns after SIGTERM without reaping. Use this
/// when the next destructor restores a tree or releases an exclusive lock:
/// `kill_on_drop` is SIGKILL of the leader PID only. Callers must spawn with
/// `process_group(0)` on Unix. Windows has no process groups; only the
/// leader is killed and waited.
pub fn terminate_group_kill_wait(
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> GroupKillWaitOutcome {
    terminate_group_kill_wait_status(child, timeout)
}

/// Why a destructive process-group teardown could not prove that no member
/// remains. A reaped leader is deliberately carried separately: its exit is
/// not evidence that descendants have left the group.
#[derive(Debug)]
pub enum GroupContainmentFailure {
    LeaderPinUnavailable,
    GroupSignal(std::io::Error),
    GroupProbe(std::io::Error),
    LeaderPoll(std::io::Error),
    GroupInventory(std::io::Error),
    GroupDrainDeadline(GroupMemberSnapshot),
}

/// Bounded, non-secret kernel identity snapshot for an unproven group drain.
#[derive(Debug, Default)]
pub struct GroupMemberSnapshot {
    pub members: Vec<GroupMemberIdentity>,
    pub truncated: bool,
}

#[derive(Debug)]
pub struct GroupMemberIdentity {
    pub pid: i32,
    pub state: char,
    pub parent_pid: i32,
}

/// Result of destructive process-group teardown.
///
/// Only `Quiesced` proves both facts needed by callers that restore shared
/// files or release write-exclusion: the group empty oracle fired and the
/// leader was reaped. `Unproven` may still carry the leader's status, but that
/// status must never be used as a substitute for group absence.
#[derive(Debug)]
pub enum GroupKillWaitOutcome {
    Quiesced(std::process::ExitStatus),
    Unproven {
        leader_status: Option<std::process::ExitStatus>,
        failure: GroupContainmentFailure,
    },
}

/// [`terminate_group_kill_wait`] with the reaped leader status preserved.
///
/// The first operation on Unix is capture-and-signal while the leader is
/// still unreaped. In particular, do not call `try_wait` before this: a
/// normally exited leader can leave live descendants in its process group,
/// and reaping it would discard the identity pin needed to signal that group.
pub fn terminate_group_kill_wait_status(
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> GroupKillWaitOutcome {
    let deadline = Instant::now() + timeout;
    #[cfg(unix)]
    {
        let Some((pgid, start)) = child
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(capture_leader_pin)
        else {
            let _ = child.start_kill();
            return GroupKillWaitOutcome::Unproven {
                leader_status: child.try_wait().ok().flatten(),
                failure: GroupContainmentFailure::LeaderPinUnavailable,
            };
        };
        match signal_pinned_group(pgid, start, libc::SIGKILL) {
            Err(error) if is_esrch(&error) => match child.try_wait() {
                Ok(Some(observed)) => return GroupKillWaitOutcome::Quiesced(observed),
                Ok(None) => {
                    return GroupKillWaitOutcome::Unproven {
                        leader_status: None,
                        failure: GroupContainmentFailure::LeaderPinUnavailable,
                    };
                }
                Err(error) => {
                    return GroupKillWaitOutcome::Unproven {
                        leader_status: None,
                        failure: GroupContainmentFailure::LeaderPoll(error),
                    };
                }
            },
            Err(error) => {
                let _ = child.start_kill();
                return GroupKillWaitOutcome::Unproven {
                    leader_status: child.try_wait().ok().flatten(),
                    failure: GroupContainmentFailure::GroupSignal(error),
                };
            }
            Ok(()) => {}
        }
        let mut leader_status = None;
        while Instant::now() < deadline {
            let nonleader_remains = match group_has_live_nonleader(pgid) {
                Ok(remains) => remains,
                Err(error) => {
                    return GroupKillWaitOutcome::Unproven {
                        leader_status: None,
                        failure: GroupContainmentFailure::GroupInventory(error),
                    };
                }
            };
            if !nonleader_remains {
                if leader_status.is_none() {
                    match child.try_wait() {
                        Ok(Some(observed)) => leader_status = Some(observed),
                        Ok(None) => {}
                        Err(error) => {
                            return GroupKillWaitOutcome::Unproven {
                                leader_status: None,
                                failure: GroupContainmentFailure::LeaderPoll(error),
                            };
                        }
                    }
                }
                if let Some(observed) = leader_status {
                    #[cfg(target_os = "linux")]
                    return GroupKillWaitOutcome::Quiesced(observed);
                    #[cfg(not(target_os = "linux"))]
                    {
                        // The destructive signal already happened under the
                        // leader pin. Continue this observation-only probe for
                        // the original deadline: a recycled PGID can cause a
                        // safe false-populated result, but can never become a
                        // signal or reap target.
                        match signal_group(pgid, 0) {
                            Err(error) if is_esrch(&error) => {
                                return GroupKillWaitOutcome::Quiesced(observed);
                            }
                            Err(error) if error.raw_os_error() != Some(libc::EPERM) => {
                                return GroupKillWaitOutcome::Unproven {
                                    leader_status: Some(observed),
                                    failure: GroupContainmentFailure::GroupProbe(error),
                                };
                            }
                            Ok(()) | Err(_) => {}
                        }
                    }
                }
            }
            std::thread::yield_now();
        }
        return GroupKillWaitOutcome::Unproven {
            leader_status,
            failure: GroupContainmentFailure::GroupDrainDeadline(group_member_snapshot(pgid)),
        };
    }
    #[cfg(not(unix))]
    {
        let status = None;
        let _ = child.start_kill();
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(observed)) => return GroupKillWaitOutcome::Quiesced(observed),
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(error) => {
                    return GroupKillWaitOutcome::Unproven {
                        leader_status: status,
                        failure: GroupContainmentFailure::LeaderPoll(error),
                    };
                }
            }
        }
        GroupKillWaitOutcome::Unproven {
            leader_status: status,
            failure: GroupContainmentFailure::GroupDrainDeadline(GroupMemberSnapshot::default()),
        }
    }
}

#[cfg(target_os = "linux")]
fn group_member_snapshot(pgid: libc::pid_t) -> GroupMemberSnapshot {
    const MAX_MEMBERS: usize = 32;
    let mut snapshot = GroupMemberSnapshot::default();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return snapshot;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some((_, fields)) = stat.rsplit_once(") ") else {
            continue;
        };
        let mut fields = fields.split_whitespace();
        let state = fields.next().and_then(|value| value.chars().next());
        let parent_pid = fields.next().and_then(|value| value.parse::<i32>().ok());
        let member_pgid = fields.next().and_then(|value| value.parse::<i32>().ok());
        if member_pgid != Some(pgid) {
            continue;
        }
        if snapshot.members.len() == MAX_MEMBERS {
            snapshot.truncated = true;
            break;
        }
        if let (Some(state), Some(parent_pid)) = (state, parent_pid) {
            snapshot.members.push(GroupMemberIdentity {
                pid,
                state,
                parent_pid,
            });
        }
    }
    snapshot
}

#[cfg(all(unix, not(target_os = "linux")))]
fn group_member_snapshot(_pgid: libc::pid_t) -> GroupMemberSnapshot {
    GroupMemberSnapshot::default()
}

/// Report whether the pinned group contains any non-zombie member other than
/// its leader. The daemon is deliberately not a subreaper: orphan zombies are
/// owned by their real reaper and are inert, while any process capable of
/// further filesystem effects keeps the outcome unproven.
#[cfg(target_os = "linux")]
fn group_has_live_nonleader(pgid: libc::pid_t) -> std::io::Result<bool> {
    let mut member_remains = false;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        if pid == pgid {
            continue;
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let Some((_, fields)) = stat.rsplit_once(") ") else {
            continue;
        };
        let mut fields = fields.split_whitespace();
        let state = fields.next();
        let _ppid = fields.next();
        let member_pgid = fields
            .next()
            .and_then(|value| value.parse::<libc::pid_t>().ok());
        if member_pgid != Some(pgid) {
            continue;
        }
        if state != Some("Z") {
            member_remains = true;
        }
    }
    Ok(member_remains)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn group_has_live_nonleader(_pgid: libc::pid_t) -> std::io::Result<bool> {
    // These hosts do not expose Linux's adopted-child `/proc` inventory.
    // Reap the leader, then let the non-destructive group oracle decide: any
    // surviving descendant (including a zombie) remains populated/unproven.
    Ok(false)
}

/// Terminate a caller-created Unix process group and reap its leader.
///
/// `std::process::Child::id()` is the spawn-cached pid and is never
/// cleared after `wait`, so it is not an attribution proof. Destructive
/// group signals (`SIGTERM` / `SIGKILL`) require the unreaped-leader pin
/// (`waitid` plus process-start identity) at signal time. After the
/// leader has been reaped, this falls back to a direct-child kill/wait
/// and must not `kill(-pgid)`. Callers hold exclusive `&mut Child`, so a
/// concurrent reaper cannot currently race the pin; the pin is still
/// required because the cached integer outlives the child.
pub fn terminate_group_sync(child: &mut std::process::Child, grace: Duration) {
    #[cfg(unix)]
    {
        let pgid = child.id() as i32;
        if let Some((_, start)) = capture_leader_pin(pgid) {
            match signal_pinned_group(pgid, start, libc::SIGTERM) {
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
                    Err(_) => {
                        // Wait identity is unknown; do not SIGKILL a cached pgid.
                        let _ = child.kill();
                        let _ = child.wait();
                        return;
                    }
                }
            }
            if leader_pin_holds(pgid, start) {
                let _ = signal_pinned_group(pgid, start, libc::SIGKILL);
            }
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
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn bounded_drain_short_output_is_byte_identical_with_zero_dropped() {
        let input = b"hello\nworld\n".to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input.clone())), 8, 8)
            .join()
            .await;

        assert_eq!(capture.bytes, input);
        assert_eq!(capture.dropped_bytes, 0);
    }

    #[tokio::test]
    async fn bounded_drain_output_exactly_at_budget_drops_nothing() {
        let input = b"abcdefghijklmnop".to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input.clone())), 8, 8)
            .join()
            .await;

        assert_eq!(capture.bytes, input);
        assert_eq!(capture.dropped_bytes, 0);
    }

    #[tokio::test]
    async fn bounded_drain_keeps_head_and_tail_and_reports_exact_dropped_count() {
        let input = b"aaaabbbbccccdddd".to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input)), 4, 4)
            .join()
            .await;

        assert_eq!(capture.bytes, b"aaaadddd");
        assert_eq!(capture.dropped_bytes, 8);
    }

    #[tokio::test]
    async fn bounded_drain_tail_only_mode_matches_harness_semantics() {
        let input = b"0123456789abcdef".to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input)), 0, 6)
            .join()
            .await;

        assert_eq!(capture.bytes, b"abcdef");
        assert_eq!(capture.dropped_bytes, 10);
    }

    #[tokio::test]
    async fn bounded_drain_memory_stays_bounded_for_huge_input() {
        let input = vec![b'x'; CHILD_PIPE_CAPTURE_BYTES * 16 + 123];

        let capture = spawn_bounded_pipe_drain(
            Some(std::io::Cursor::new(input.clone())),
            CHILD_PIPE_CAPTURE_HEAD_BYTES,
            CHILD_PIPE_CAPTURE_TAIL_BYTES,
        )
        .join()
        .await;

        assert!(capture.bytes.len() <= CHILD_PIPE_CAPTURE_BYTES);
        assert_eq!(capture.dropped_bytes, input.len() - capture.bytes.len());
    }

    #[tokio::test]
    async fn bounded_drain_cuts_on_utf8_boundary_without_panic() {
        let input = "αβγδεζηθικλμ".as_bytes().to_vec();

        let capture = spawn_bounded_pipe_drain(Some(std::io::Cursor::new(input.clone())), 5, 5)
            .join()
            .await;

        assert!(std::str::from_utf8(&capture.bytes).is_ok());
        assert!(capture.bytes.len() <= 10);
        assert_eq!(capture.dropped_bytes, input.len() - capture.bytes.len());
    }

    #[tokio::test]
    async fn bounded_drain_stdout_and_stderr_budgets_are_independent() {
        let stdout =
            spawn_bounded_pipe_drain(Some(std::io::Cursor::new(b"aaaabbbb".to_vec())), 2, 2)
                .join()
                .await;
        let stderr =
            spawn_bounded_pipe_drain(Some(std::io::Cursor::new(b"ccccdddd".to_vec())), 2, 2)
                .join()
                .await;

        assert_eq!(stdout.bytes, b"aabb");
        assert_eq!(stdout.dropped_bytes, 4);
        assert_eq!(stderr.bytes, b"ccdd");
        assert_eq!(stderr.dropped_bytes, 4);
    }

    #[tokio::test]
    async fn bounded_drain_aborted_drain_returns_bytes_captured_so_far() {
        let (mut writer, reader) = tokio::io::duplex(64);
        let drain = spawn_bounded_pipe_drain(Some(reader), 8, 8);
        writer.write_all(b"partial").await.unwrap();
        for _ in 0..100 {
            if !drain.snapshot().bytes.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }

        drain.abort();
        let capture = drain.join().await;

        assert_eq!(capture.bytes, b"partial");
        assert_eq!(capture.dropped_bytes, 0);
    }

    #[test]
    fn bounded_drain_gate_keeps_touched_child_pipe_paths_on_shared_helper() {
        let core_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../cockpit-core/src");
        let touched_files = [
            core_src.join("harness/spawn.rs"),
            core_src.join("tools/bash/mod.rs"),
            core_src.join("tools/custom.rs"),
        ];
        let bad_read = ["read", "_to_end"].concat();
        let bad_output = [".", "output()"].concat();
        for path in touched_files {
            let source = std::fs::read_to_string(&path).unwrap();
            assert!(
                !source.contains(&bad_read),
                "{} still has an unbounded pipe read",
                path.display()
            );
            assert!(
                !source.contains(&bad_output),
                "{} still has Command::output capture",
                path.display()
            );
        }
    }

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

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn validation_supervisor_reaps_adopted_exit_without_killing_live_leader() {
        use std::os::unix::ffi::OsStrExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let release = tmp.path().join("release.fifo");
        let orphan_pid = tmp.path().join("orphan.pid");
        let fifo = std::ffi::CString::new(release.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let script = format!(
            "supervisor=$PPID\n\
             sh -c '(read ignored < \"$1\") & echo \"$!\" > \"$2\"' inner '{}' '{}'\n\
             orphan=$(cat '{}')\n\
             while :; do set -- $(cat \"/proc/$orphan/stat\"); [ \"$4\" = \"$supervisor\" ] && break; done\n\
             printf x > '{}'\n\
             while [ -e \"/proc/$orphan\" ]; do :; done\n\
             exit 7\n",
            release.display(),
            orphan_pid.display(),
            orphan_pid.display(),
            release.display(),
        );
        let mut supervisor = spawn_validation_supervisor(
            std::ffi::OsStr::new("sh"),
            &["-c", &script],
            tmp.path(),
            &[],
        )
        .unwrap();

        let status = supervisor.wait().await.unwrap();

        assert_eq!(
            status.code(),
            Some(7),
            "an adopted-child SIGCHLD must not replace the live leader's natural result"
        );
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
        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .current_dir(tmp.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let mut child = command.spawn().unwrap();
        let pid = child.id();
        wait_for_file(&ready);
        wait_for_file(&heartbeat);

        terminate_group_async(&mut child, pid, Duration::from_millis(200)).await;

        tokio::time::sleep(Duration::from_millis(600)).await;
        let mtime_after_kill = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        tokio::time::sleep(Duration::from_millis(400)).await;
        let mtime_later = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        assert_eq!(
            mtime_after_kill, mtime_later,
            "descendant heartbeat kept updating after process-group termination"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_process_tree_guard_configures_a_fresh_group_without_spawning() {
        let mut command = tokio::process::Command::new("prohibited-real-process");
        let guard = ProcessTreeGuard::prepare(&mut command);
        assert!(guard.is_ok());
        let guard = guard.expect("allocate");
        assert!(
            !guard.group_is_bound(),
            "allocate must not place a process-group member"
        );
        assert!(
            !guard.group_is_populated().expect("unbound group is empty"),
            "allocate must not fabricate a populated group"
        );
        assert_eq!(unix_group_signal_target(41), -41);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_process_tree_guard_tracks_assigned_process_group() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ProcessTreeGuard::allocate().expect("allocate process-group guard");
        guard.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn stopped child");
        guard
            .assign(&child)
            .expect("record process-group membership");
        assert!(
            guard.group_is_bound(),
            "assign must bind the process-group identity"
        );
        assert!(
            guard
                .group_is_populated()
                .expect("process-group existence probe"),
            "membership must be visible after assign"
        );
        guard.resume(&child).expect("unix resume is a no-op");
        guard.terminate().expect("SIGKILL process group");
        let _ = child.wait().await;
        let mut empty = false;
        for _ in 0..50 {
            if !guard
                .group_is_populated()
                .expect("process-group existence probe")
            {
                empty = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(empty, "SIGKILL plus reap must drain the process group");
        assert!(
            guard.group_terminate_signaled(),
            "first terminate must consume signal authority"
        );
        guard.terminate().expect("second terminate is a no-op");
        guard.release_group();
        assert!(!guard.group_is_bound());
        guard
            .terminate()
            .expect("released identity is not re-signaled");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn assign_failure_is_unattributable_not_empty() {
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        // No process_group(0): the child is not a group leader, so assign
        // cannot bind this guard to a fresh group.
        let guard = ProcessTreeGuard::allocate().expect("allocate");
        let mut child = command.spawn().expect("spawn");
        assert!(guard.assign(&child).is_err());
        assert!(!guard.group_is_bound());
        assert!(guard.group_is_unattributable());
        assert_eq!(
            guard.group_population().expect("population"),
            GroupPopulation::Unattributable
        );
        assert!(
            guard.group_is_populated().is_err(),
            "spawned-but-unbound must not report empty"
        );
        guard.release_group();
        assert!(
            guard.group_is_unattributable(),
            "release after empty proof must not wash assign-failure into unbound-empty"
        );
        // A second assign of a real group leader must not launder this
        // terminal membership into a fresh Bound identity.
        let mut leader = tokio::process::Command::new("sh");
        leader
            .args(["-c", "sleep 30"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        guard.apply_spawn_flags(&mut leader);
        let mut second = leader.spawn().expect("spawn group leader");
        let second_err = guard
            .assign(&second)
            .expect_err("unattributable assign must be rejected");
        assert!(
            second_err
                .to_string()
                .contains(PROCESS_GROUP_MEMBERSHIP_UNATTRIBUTABLE),
            "reject reason must name unattributable membership, got {second_err}"
        );
        assert!(
            guard.group_is_unattributable(),
            "rejected second assign must not overwrite Unattributable"
        );
        assert_eq!(
            guard.group_population().expect("population"),
            GroupPopulation::Unattributable
        );
        let _ = child.start_kill();
        let _ = child.wait().await;
        let _ = second.start_kill();
        let _ = second.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn release_signal_authority_forgets_pgid_without_claiming_empty() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ProcessTreeGuard::allocate().expect("allocate");
        guard.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn");
        guard.assign(&child).expect("bind");
        guard.terminate().expect("one-shot SIGKILL");
        guard.release_signal_authority();
        assert!(guard.group_is_unattributable());
        assert_eq!(
            guard.group_population().expect("population"),
            GroupPopulation::Unattributable
        );
        guard
            .terminate()
            .expect("unattributable terminate is a no-op");
        let mut leader = tokio::process::Command::new("sh");
        leader
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        guard.apply_spawn_flags(&mut leader);
        let mut second = leader.spawn().expect("spawn group leader");
        assert!(
            guard.assign(&second).is_err(),
            "released signal authority is terminal; assign must not re-bind"
        );
        assert!(guard.group_is_unattributable());
        let _ = child.wait().await;
        let _ = second.start_kill();
        let _ = second.wait().await;
    }

    #[cfg(unix)]
    fn inject_next_group_signal_errno(errno: i32) {
        TEST_GROUP_SIGNAL_ERRNO.with(|cell| cell.set(errno));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reap_without_signal_forgets_pgid_and_does_not_re_signal() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ProcessTreeGuard::allocate().expect("allocate");
        guard.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn");
        guard.assign(&child).expect("bind");
        let _ = child.start_kill();
        let _ = child.wait().await;
        assert_eq!(
            guard.group_population().expect("population"),
            GroupPopulation::Unattributable,
            "reaping the leader without SIGKILL must forget the pgid"
        );
        assert!(guard.group_is_unattributable());
        assert!(!guard.group_is_bound());
        guard
            .terminate()
            .expect("unpinned identity must not be signaled");
        assert!(
            !guard.group_terminate_signaled(),
            "forgotten identity must not consume a one-shot against a recycled pgid"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_signal_retries_while_leader_pin_holds() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ProcessTreeGuard::allocate().expect("allocate");
        guard.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn");
        guard.assign(&child).expect("bind");
        inject_next_group_signal_errno(libc::EPERM);
        assert!(
            guard.terminate().is_err(),
            "EPERM must not be treated as a successful one-shot"
        );
        assert!(
            !guard.group_terminate_signaled(),
            "failed SIGKILL must leave the one-shot open while the pin holds"
        );
        assert!(guard.group_is_bound());
        guard
            .terminate()
            .expect("retry is allowed while the unreaped leader pins the pgid");
        assert!(guard.group_terminate_signaled());
        let _ = child.wait().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_signal_then_reap_forgets_pgid() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ProcessTreeGuard::allocate().expect("allocate");
        guard.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn");
        guard.assign(&child).expect("bind");
        inject_next_group_signal_errno(libc::EPERM);
        assert!(guard.terminate().is_err());
        let _ = child.start_kill();
        let _ = child.wait().await;
        assert_eq!(
            guard.group_population().expect("population"),
            GroupPopulation::Unattributable,
            "EPERM then reap must not keep a stale pgid for the next drain retry"
        );
        guard
            .terminate()
            .expect("pin-loss after failed signal must not SIGKILL a recycled pgid");
        assert!(!guard.group_is_bound());
        assert!(!guard.group_terminate_signaled());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn successful_signal_empty_oracle_survives_leader_reap() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ProcessTreeGuard::allocate().expect("allocate");
        guard.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("spawn");
        guard.assign(&child).expect("bind");
        guard.terminate().expect("SIGKILL");
        let _ = child.wait().await;
        let mut empty = false;
        for _ in 0..50 {
            match guard.group_population().expect("population") {
                GroupPopulation::Empty => {
                    empty = true;
                    break;
                }
                GroupPopulation::Populated => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                GroupPopulation::Unattributable => {
                    panic!("successful SIGKILL must keep the identity for the empty oracle")
                }
            }
        }
        assert!(empty, "SIGKILL plus reap must drain the process group");
        assert!(guard.group_terminate_signaled());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exit_observation_pins_group_identity_until_termination_reaps_leader() {
        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg("exit 0")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .process_group(0);
        let mut child = command.spawn().unwrap();
        let pid = child.id().unwrap();

        wait_for_exit_without_reaping(pid).await.unwrap();
        assert_eq!(child.id(), Some(pid), "exit observation must not reap");

        let status = terminate_group_and_reap_status_async(&mut child, Some(pid), Duration::ZERO)
            .await
            .unwrap();
        assert!(status.success());
        assert_eq!(child.id(), None, "termination must finish by reaping once");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn leader_pin_requires_start_identity_sameness() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = command.spawn().expect("spawn");
        let pid = libc::pid_t::try_from(child.id().expect("pid")).expect("pid_t");
        let start = crate::daemon_lifecycle::process_start_identity(pid as u32).expect("start");
        assert!(
            leader_pin_holds(pid, start),
            "assigned unreaped leader must pin"
        );
        let mismatch = crate::daemon_lifecycle::ProcessStartIdentity {
            primary: start.primary.wrapping_add(1),
            secondary: start.secondary,
        };
        assert!(
            !leader_pin_holds(pid, mismatch),
            "waitid parenthood is not guard-child sameness"
        );
        let _ = child.start_kill();
        let _ = child.wait().await;
        assert!(
            !leader_pin_holds(pid, start),
            "reaped leader must not remain a signal target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminate_group_sync_does_not_signal_a_reaped_std_child_pgid() {
        use std::os::unix::process::CommandExt as _;
        use std::process::{Command, Stdio};

        let mut command = Command::new("sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = command.spawn().expect("spawn");
        let _ = child.kill();
        let _ = child.wait();
        TEST_GROUP_SIGNAL_COUNT.with(|cell| cell.set(0));
        terminate_group_sync(&mut child, Duration::from_millis(50));
        assert_eq!(
            TEST_GROUP_SIGNAL_COUNT.with(|cell| cell.get()),
            0,
            "std Child::id() survives wait; a reaped leader must not be a group-signal target"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminate_group_kill_wait_reaps_term_ignoring_descendants_before_return() {
        let tmp = tempfile::tempdir().unwrap();
        let heartbeat = tmp.path().join("heartbeat");
        let ready = tmp.path().join("ready");
        let script = format!(
            "trap '' TERM; ( trap '' TERM; while true; do touch '{}'; sleep 0.05; done ) & touch '{}'; sleep 30",
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
        wait_for_file(&ready);
        wait_for_file(&heartbeat);

        let started = std::time::Instant::now();
        let outcome = terminate_group_kill_wait_status(&mut child, Duration::from_secs(2));
        assert!(
            matches!(outcome, GroupKillWaitOutcome::Quiesced(_)),
            "successful group drain must be distinguished from leader-only exit: {outcome:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "group SIGKILL wait should reap well under its timeout cap"
        );

        let mtime_after_kill = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mtime_later = std::fs::metadata(&heartbeat)
            .ok()
            .and_then(|m| m.modified().ok());
        assert_eq!(
            mtime_after_kill, mtime_later,
            "descendant heartbeat kept updating after terminate_group_kill_wait returned"
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminate_group_kill_wait_reports_signal_failure_as_unproven() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("cat");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut child = runtime.block_on(async { command.spawn().unwrap() });
        let _stdin = child.stdin.take().unwrap();

        inject_next_group_signal_errno(libc::EPERM);
        let outcome = terminate_group_kill_wait_status(&mut child, Duration::ZERO);
        assert!(matches!(
            outcome,
            GroupKillWaitOutcome::Unproven {
                failure: GroupContainmentFailure::GroupSignal(ref error),
                ..
            } if error.raw_os_error() == Some(libc::EPERM)
        ));

        let cleanup = terminate_group_kill_wait_status(&mut child, Duration::from_secs(2));
        assert!(matches!(cleanup, GroupKillWaitOutcome::Quiesced(_)));
    }

    #[cfg(unix)]
    #[test]
    fn terminate_group_kill_wait_reports_zero_budget_drain_as_unproven() {
        use std::process::Stdio;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut command = tokio::process::Command::new("cat");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = runtime.block_on(async { command.spawn().unwrap() });
        let _stdin = child.stdin.take().unwrap();

        let outcome = terminate_group_kill_wait_status(&mut child, Duration::ZERO);
        assert!(matches!(
            outcome,
            GroupKillWaitOutcome::Unproven {
                failure: GroupContainmentFailure::GroupDrainDeadline(_),
                ..
            }
        ));

        let cleanup = terminate_group_kill_wait_status(&mut child, Duration::from_secs(2));
        assert!(matches!(cleanup, GroupKillWaitOutcome::Quiesced(_)));
    }

    #[cfg(windows)]
    #[test]
    fn windows_allocate_creates_an_empty_job_without_spawning() {
        let guard = ProcessTreeGuard::allocate().expect("CreateJobObjectW");
        assert!(guard.job_is_open(), "allocated job handle must stay open");
        assert_eq!(
            guard
                .active_process_count()
                .expect("QueryInformationJobObject"),
            0,
            "allocate must not place a process"
        );
        let _ = ProcessTreeGuard::current_process_is_in_job().expect("IsProcessInJob");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_process_tree_guard_job_accounts_for_assigned_process() {
        use std::process::Stdio;

        let mut command = tokio::process::Command::new("cmd.exe");
        command
            .args(["/C", "ping", "-n", "20", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ProcessTreeGuard::allocate().expect("CreateJobObjectW");
        guard.apply_spawn_flags(&mut command);
        let mut child = command.spawn().expect("CreateProcessW CREATE_SUSPENDED");
        guard.assign(&child).expect("AssignProcessToJobObject");
        assert!(
            guard.job_is_open(),
            "job handle must stay open after assign"
        );
        assert!(
            guard
                .active_process_count()
                .expect("QueryInformationJobObject")
                >= 1,
            "membership must be visible before ResumeThread"
        );
        guard.resume(&child).expect("ResumeThread");
        guard.terminate().expect("TerminateJobObject");
        let mut empty = false;
        for _ in 0..50 {
            if guard
                .active_process_count()
                .expect("QueryInformationJobObject")
                == 0
            {
                empty = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(empty, "TerminateJobObject must drain the job");
        let _ = child.try_wait();
    }
}
