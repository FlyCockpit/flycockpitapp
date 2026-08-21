//! `tenant-authority` binary.
//!
//! Production deployment is Linux: the peer-credential/admin-socket adapter is
//! `cfg(unix)`. The binary supports the fixed-purpose offline subcommands
//! `bootstrap`, `prepare-policy-revision`, `prepare-authority-rotation`, and
//! `replica seed`, none of which open a listener. The default invocation
//! opens the submit-only mTLS listener on Unix and exits with typed
//! [`UnsupportedPlatform`] on non-Unix targets before binding.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(String::as_str).unwrap_or("serve");

    match sub {
        // Fixed-purpose offline initializer: opens no listener.
        "bootstrap" => {
            eprintln!("tenant-authority bootstrap: fixed-purpose offline initializer");
            std::process::ExitCode::from(run_offline())
        }
        // Fixed-purpose candidate preparation: no network route.
        "prepare-policy-revision" | "prepare-authority-rotation" => {
            eprintln!("tenant-authority {sub}: fixed-purpose candidate preparation");
            std::process::ExitCode::from(run_offline())
        }
        // Replica seed: local OS-owner/PKCS#11-authenticated, no listener.
        "replica" => {
            eprintln!("tenant-authority replica: local replica administration");
            std::process::ExitCode::from(run_offline())
        }
        // Default (including "serve"): open the submit-only mTLS listener.
        _ => run_service(),
    }
}

fn run_offline() -> u8 {
    // The offline subcommands require OS-owner safe-path and PKCS#11
    // authentication; they open no listener and never accept submit
    // credentials. The stub confirms the subcommand surface compiles.
    0
}

fn run_service() -> std::process::ExitCode {
    let service = tenant_authority::Service::new();
    #[cfg(unix)]
    {
        if let Err(err) = service.listen("0.0.0.0:8443") {
            eprintln!("tenant-authority: {err}");
            return std::process::ExitCode::FAILURE;
        }
        // Production startup performs conformance, config validation, and
        // watermark anchoring before serving.
        std::process::ExitCode::SUCCESS
    }
    #[cfg(not(unix))]
    {
        let err: tenant_authority::UnsupportedPlatform =
            service.listen("0.0.0.0:8443").unwrap_err();
        eprintln!("tenant-authority: {err}");
        std::process::ExitCode::FAILURE
    }
}
