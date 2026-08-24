//! Privileged Linux containment broker entry point.
//!
//! This is intentionally a separate executable from `cockpit`: installations
//! grant cgroup authority to this service, never to the interactive CLI or
//! daemon. The service manager supplies the sole allowed workload uid/gid.

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::path::PathBuf;

    // Do this before argument parsing, allocation, account lookup, or opening
    // the service-manager capability. Root broker memory and descriptors must
    // never become ptrace/core-dump material during partial startup.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut uid = None;
    let mut gid = None;
    let mut socket = None;
    let mut capability_fd = None;
    let mut doctor = false;
    let mut prepare_cgroup_root = false;
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--allowed-uid") => uid = Some(parse_id(args.next(), "--allowed-uid")?),
            Some("--allowed-gid") => gid = Some(parse_id(args.next(), "--allowed-gid")?),
            Some("--socket") => socket = args.next().map(PathBuf::from),
            Some("--capability-fd") => capability_fd = Some(parse_id(args.next(), "--capability-fd")? as i32),
            Some("--doctor") => doctor = true,
            Some("--prepare-cgroup-root") => prepare_cgroup_root = true,
            _ => return Err(invalid("unknown or non-UTF-8 argument")),
        }
    }
    let uid = uid.ok_or_else(|| invalid("--allowed-uid is required"))?;
    if uid == 0 {
        return Err(invalid("--allowed-uid must identify a non-root daemon account"));
    }
    if doctor && prepare_cgroup_root {
        return Err(invalid("--doctor and --prepare-cgroup-root are mutually exclusive"));
    }
    if doctor {
        let config = cockpit_core::process_containment::LinuxBrokerConfig {
            socket_path: socket.ok_or_else(|| invalid("--socket is required for --doctor"))?,
            expected_broker_uid: 0,
            capability_fd,
        };
        return cockpit_core::process_containment::doctor_linux_containment_broker(config);
    }
    let gid = match gid {
        Some(gid) => gid,
        None => primary_gid(uid)?,
    };
    let mut config = cockpit_core::process_containment::LinuxBrokerServerConfig::production(uid, gid);
    if prepare_cgroup_root {
        if socket.is_some() || capability_fd.is_some() {
            return Err(invalid("cgroup preparation accepts only --allowed-uid and --allowed-gid"));
        }
        return cockpit_core::process_containment::prepare_linux_containment_broker_cgroup_root(&config);
    }
    if let Some(path) = socket {
        config.socket_path = path;
    }
    config.capability_fd = capability_fd
        .or_else(|| cockpit_core::process_containment::inherited_linux_broker_capability_fd())
        .ok_or_else(|| invalid("named containment capability fd is required"))?;
    cockpit_core::process_containment::run_linux_containment_broker(config)
}

#[cfg(target_os = "linux")]
fn primary_gid(uid: u32) -> std::io::Result<u32> {
    let mut buffer_size = 1024_usize;
    loop {
        let mut record: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; buffer_size];
        let status = unsafe {
            libc::getpwuid_r(uid, &mut record, buffer.as_mut_ptr().cast(), buffer.len(), &mut result)
        };
        if status == libc::ERANGE {
            buffer_size = buffer_size
                .checked_mul(2)
                .filter(|size| *size <= 1024 * 1024)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "account record exceeds 1 MiB",
                    )
                })?;
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status));
        }
        if result.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "allowed uid has no account record",
            ));
        }
        return Ok(record.pw_gid);
    }
}

#[cfg(target_os = "linux")]
fn parse_id(value: Option<std::ffi::OsString>, name: &str) -> std::io::Result<u32> {
    value
        .and_then(|value| value.into_string().ok())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid(format!("{name} requires a numeric id")))
}

#[cfg(target_os = "linux")]
fn invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("cockpit-containment-broker is supported only on Linux");
    std::process::exit(1);
}
