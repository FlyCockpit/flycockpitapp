#!/usr/bin/env bash
set -euo pipefail

out_dir="${1:-target/dist}"
completion_dir="$out_dir/completions"
man_dir="$out_dir/man"

mkdir -p "$completion_dir" "$man_dir"

cargo run --locked -p cockpit-cli -- completion bash > "$completion_dir/cockpit.bash"
cargo run --locked -p cockpit-cli -- completion zsh > "$completion_dir/_cockpit"
cargo run --locked -p cockpit-cli -- completion fish > "$completion_dir/cockpit.fish"
cargo run --locked -p cockpit-cli --example generate-manpages -- "$man_dir"
