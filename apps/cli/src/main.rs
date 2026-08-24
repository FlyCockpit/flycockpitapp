fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    if std::env::var_os("LISTEN_FDNAMES")
        .is_some_and(|names| names.as_encoded_bytes().split(|byte| *byte == b':').any(|name| name == b"flycockpit-containment-capability"))
        && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        eprintln!("cockpit: could not protect the containment capability");
        return std::process::ExitCode::FAILURE;
    }
    cockpit_cli::main_entry()
}
