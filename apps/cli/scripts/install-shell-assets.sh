#!/usr/bin/env bash
# Best-effort post-install helper for cargo-dist shell installs.
# It installs generated completions/man pages when standard user locations are
# detectable. Failures are intentionally non-fatal.

set -u

if [ "${COCKPIT_SKIP_SHELL_ASSETS:-}" = "1" ]; then
  exit 0
fi

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd -P)" || exit 0
completion_src="$script_dir/completions"
man_src="$script_dir/man"

copy_file() {
  src="$1"
  dest="$2"
  [ -f "$src" ] || return 0
  mkdir -p "$(dirname -- "$dest")" 2>/dev/null || return 0
  cp "$src" "$dest" 2>/dev/null || return 0
}

home="${HOME:-}"
xdg_data="${XDG_DATA_HOME:-}"
if [ -z "$xdg_data" ] && [ -n "$home" ]; then
  xdg_data="$home/.local/share"
fi

if [ -n "$xdg_data" ]; then
  copy_file "$completion_src/cockpit.bash" "$xdg_data/bash-completion/completions/cockpit"
  copy_file "$completion_src/_cockpit" "$xdg_data/zsh/site-functions/_cockpit"
  copy_file "$completion_src/cockpit.fish" "$xdg_data/fish/vendor_completions.d/cockpit.fish"
  copy_file "$man_src/cockpit.1" "$xdg_data/man/man1/cockpit.1"
  if [ -d "$man_src" ]; then
    for page in "$man_src"/cockpit-*.1; do
      [ -f "$page" ] || continue
      copy_file "$page" "$xdg_data/man/man1/$(basename -- "$page")"
    done
  fi
fi

exit 0
