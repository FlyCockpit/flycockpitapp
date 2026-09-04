//! `tenant-authority` binary.
//!
//! **Reference-only:** this crate documents the customer-operated tenant-authority
//! contract but does not yet implement the production listener, PKCS#11 signing,
//! or per-handler evidence verification. The fixed-purpose offline subcommands
//! (`bootstrap`, `prepare-policy-revision`, `prepare-authority-rotation`, `replica
//! seed`) compile the subcommand surface but are not wired. The default `serve`
//! subcommand fails closed with a typed not-implemented error on Unix and with
//! [`tenant_authority::UnsupportedPlatform`] on non-Unix targets.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(String::as_str).unwrap_or("serve");

    match sub {
        // Fixed-purpose offline initializer: opens no listener (not wired).
        "bootstrap" => {
            eprintln!("tenant-authority bootstrap: fixed-purpose offline initializer");
            std::process::ExitCode::from(run_offline())
        }
        // Fixed-purpose candidate preparation: no network route (not wired).
        "prepare-policy-revision" | "prepare-authority-rotation" => {
            eprintln!("tenant-authority {sub}: fixed-purpose candidate preparation");
            std::process::ExitCode::from(run_offline())
        }
        // Replica seed: local OS-owner/PKCS#11-authenticated, no listener (not wired).
        "replica" => {
            eprintln!("tenant-authority replica: local replica administration");
            std::process::ExitCode::from(run_offline())
        }
        // Default (including "serve"): submit-only mTLS listener (not implemented).
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
    match service.listen("0.0.0.0:8443") {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("tenant-authority: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
