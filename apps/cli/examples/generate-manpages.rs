//! Generate release man pages for the cockpit CLI.

fn main() -> std::io::Result<()> {
    let output = std::env::args_os()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target/dist-manpages"));
    cockpit_cli::manpages::generate_manpages(output)
}
