#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
if [ "$PWD" != "$repo_root" ]; then
  echo "generate-release-assets.sh must run from the repository root" >&2
  exit 2
fi
if [ "${CARGO_TARGET_DIR:-target}" != "target" ]; then
  echo "CARGO_TARGET_DIR must be the repository-owned target directory" >&2
  exit 2
fi

out_dir="${1:-target/dist}"
case "$out_dir" in
  target/dist|target/distrib) ;;
  *) echo "output must be target/dist or target/distrib" >&2; exit 2 ;;
esac
completion_dir="$out_dir/completions"
man_dir="$out_dir/man"

mkdir -p "$completion_dir" "$man_dir"

cargo run --locked -p cockpit-cli --example generate-completions -- bash > "$completion_dir/cockpit.bash"
cargo run --locked -p cockpit-cli --example generate-completions -- zsh > "$completion_dir/_cockpit"
cargo run --locked -p cockpit-cli --example generate-completions -- fish > "$completion_dir/cockpit.fish"
cargo run --locked -p cockpit-cli --example generate-manpages -- "$man_dir"
python3 apps/cli/scripts/generate-runtime-docs.py --check
