#!/usr/bin/env python3
"""Patch cargo-dist's generated installers with Cockpit release assets.

cargo-dist 0.32 can include prebuilt files in archives/installers, but it has no
first-class completions/manpage install stanza. Keep the patch small and fail if
upstream templates change so release CI does not silently drop assets.
"""

from __future__ import annotations

import sys
from pathlib import Path


def patch_shell_installer(path: Path) -> None:
    text = path.read_text()
    install_needle = '''    _install_temp=$(mktemp -d "$_install_dir/tmp.XXXXXXXXXX")
    _lib_install_temp=$(mktemp -d "$_lib_install_dir/tmp.XXXXXXXXXX")
'''
    install_replacement = '''    # Private, unpredictable staging directories on the destination filesystem.
    # The final hard-link publication is atomic and fails if a target appeared.
    _old_umask=$(umask)
    umask 077
    _install_temp=$(mktemp -d "$_install_dir/.cockpit-install.XXXXXXXXXX")
    _lib_install_temp=$(mktemp -d "$_lib_install_dir/.cockpit-install.XXXXXXXXXX")
    umask "$_old_umask"
'''
    publish_needle = '''    for _bin_name in $_bins; do
        ensure mv "$_install_temp/$_bin_name" "$_install_dir"
        for _dest in $(aliases_for_binary "$_bin_name" "$_arch"); do
'''
    publish_replacement = '''    for _bin_name in $_bins; do
        _install_target="$_install_dir/$_bin_name"
        [ ! -e "$_install_target" ] && [ ! -L "$_install_target" ] \\
            || err "refusing to replace existing install target: $_install_target"
        # link(2) is same-filesystem, atomic, and has no overwrite mode. Keep the
        # staged file until publication succeeds so failure needs no rollback.
        ensure ln "$_install_temp/$_bin_name" "$_install_target"
        ensure rm "$_install_temp/$_bin_name"
        for _dest in $(aliases_for_binary "$_bin_name" "$_arch"); do
'''
    if install_replacement not in text:
        if install_needle not in text:
            raise SystemExit(f"could not find shell staging block in {path}")
        text = text.replace(install_needle, install_replacement, 1)
    if publish_replacement not in text:
        if publish_needle not in text:
            raise SystemExit(f"could not find shell publish block in {path}")
        text = text.replace(publish_needle, publish_replacement, 1)
    needle = '    say "everything\'s installed!"\n'
    replacement = '''    say "everything's installed!"

    # Best-effort shell completions and man-page install. The helper is bundled
    # into dist archives via dist-workspace.toml `include`; failures must not
    # fail the binary install.
    if [ -f "$_src_dir/install-shell-assets.sh" ]; then
        sh "$_src_dir/install-shell-assets.sh" || true
    fi
    if [ -f "$_src_dir/runtime-prerequisite-notice.sh" ]; then
        sh "$_src_dir/runtime-prerequisite-notice.sh" || true
    fi
'''
    if replacement in text:
        return
    if needle not in text:
        raise SystemExit(f"could not find shell installer insertion point in {path}")
    path.write_text(text.replace(needle, replacement, 1))


def patch_powershell_installer(path: Path) -> None:
    text = path.read_text()
    copy_needle = '''    Copy-Item "$bin_path" -Destination "$dest_dir" -ErrorAction Stop
    Remove-Item "$bin_path" -Recurse -Force -ErrorAction Stop
'''
    copy_replacement = '''    $installed_target = Join-Path "$dest_dir" "$installed_file"
    if (Test-Path -LiteralPath $installed_target) {
      throw "refusing to replace existing install target: $installed_target"
    }
    $staged_file = Join-Path "$dest_dir" (".cockpit-install-" + [Guid]::NewGuid().ToString("N"))
    try {
      Copy-Item "$bin_path" -Destination "$staged_file" -ErrorAction Stop
      # File.Move is an atomic same-volume publication and its two-argument
      # overload fails rather than replacing a target created concurrently.
      [System.IO.File]::Move($staged_file, $installed_target)
      Remove-Item "$bin_path" -Recurse -Force -ErrorAction Stop
    } catch {
      # If a later step failed after publication, restore the original absent
      # state. A pre-existing target is never touched.
      if (-not (Test-Path -LiteralPath $staged_file) -and (Test-Path -LiteralPath $installed_target)) {
        Remove-Item -LiteralPath $installed_target -Force -ErrorAction SilentlyContinue
      }
      throw
    } finally {
      Remove-Item -LiteralPath "$staged_file" -Force -ErrorAction SilentlyContinue
    }
'''
    if copy_replacement not in text:
        if copy_needle not in text:
            raise SystemExit(f"could not find PowerShell binary copy block in {path}")
        text = text.replace(copy_needle, copy_replacement, 1)

    needle = '  Write-Information "everything\'s installed!"\n'
    replacement = needle + '''  $archiveRoot = Split-Path -Parent $artifacts["bin_paths"][0]
  $notice = Join-Path $archiveRoot "runtime-prerequisite-notice.ps1"
  if (Test-Path -LiteralPath $notice -PathType Leaf) {
    & $notice
  }
'''
    if replacement in text:
        return
    if needle not in text:
        raise SystemExit(f"could not find PowerShell installer insertion point in {path}")
    path.write_text(text.replace(needle, replacement, 1))


def patch_homebrew_formula(path: Path) -> None:
    text = path.read_text()
    needle = '''    install_binary_aliases!

    # Homebrew will automatically install these, so we don't need to do that
'''
    replacement = '''    install_binary_aliases!

    bash_completion.install "completions/cockpit.bash" => "cockpit" if File.exist?("completions/cockpit.bash")
    zsh_completion.install "completions/_cockpit" if File.exist?("completions/_cockpit")
    fish_completion.install "completions/cockpit.fish" if File.exist?("completions/cockpit.fish")
    man1.install Dir["man/*.1"] unless Dir["man/*.1"].empty?

    # Homebrew will automatically install these, so we don't need to do that
'''
    if replacement in text:
        return
    if needle not in text:
        raise SystemExit(f"could not find Homebrew install hook insertion point in {path}")
    path.write_text(text.replace(needle, replacement, 1))


def main() -> int:
    if Path.cwd() != Path(__file__).resolve().parents[3]:
        raise SystemExit("patch-dist-assets.py must run from the repository root")
    distrib = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("target/distrib")
    if distrib != Path("target/distrib"):
        raise SystemExit("cargo-dist assets must remain in target/distrib")
    patch_shell_installer(distrib / "cockpit-cli-installer.sh")
    patch_powershell_installer(distrib / "cockpit-cli-installer.ps1")
    patch_homebrew_formula(distrib / "cockpit.rb")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
