//! Generate release shell completion assets.
//!
//! Release packaging runs this example against the pinned toolchain; the
//! public `cockpit completion <shell>` command mirrors it for interactive
//! use and both render the same `public_v0_1_command()` surface.

fn main() {
    let shell = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<clap_complete::Shell>().ok())
        .expect("usage: generate-completions <bash|zsh|fish>");
    clap_complete::generate(
        shell,
        &mut cockpit_cli::public_v0_1_command(),
        "cockpit",
        &mut std::io::stdout(),
    );
}
