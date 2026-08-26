//! Generate release shell completions without exposing a public CLI command.

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
