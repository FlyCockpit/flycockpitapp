//! `tenant-authority` binary.
//!
//! **Reference-only:** this crate documents the customer-operated tenant-authority
//! contract but does not yet implement the production listener, PKCS#11 signing,
//! or per-handler evidence verification. The fixed-purpose offline subcommands
//! (`bootstrap`, `prepare-policy-revision`, `prepare-authority-rotation`, `replica
//! seed`) compile the subcommand surface but are not wired and fail closed with
//! a not-implemented exit status. The default `serve` subcommand fails closed
//! with a typed not-implemented error on Unix and with
//! [`tenant_authority::UnsupportedPlatform`] on non-Unix targets.

#![forbid(unsafe_code)]

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let sub = args.get(1).map(String::as_str).unwrap_or("serve");

    match sub {
        // Fixed-purpose offline initializer: opens no listener (not wired).
        "bootstrap" => run_offline(sub),
        // Fixed-purpose candidate preparation: no network route (not wired).
        "prepare-policy-revision" | "prepare-authority-rotation" => run_offline(sub),
        // Replica seed: local OS-owner/PKCS#11-authenticated, no listener (not wired).
        "replica" => run_offline(sub),
        // Default (no subcommand) and explicit "serve": submit-only mTLS listener.
        "serve" => run_service(),
        _ => {
            eprintln!("tenant-authority: unknown subcommand '{sub}'");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run_offline(subcommand: &str) -> std::process::ExitCode {
    // The offline subcommands require OS-owner safe-path and PKCS#11
    // authentication; they open no listener and never accept submit
    // credentials. The stub confirms the subcommand surface compiles.
    eprintln!(
        "tenant-authority {subcommand}: not implemented: offline subcommand is not wired yet"
    );
    std::process::ExitCode::FAILURE
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
