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
    needle = '    say "everything\'s installed!"\n'
    replacement = '''    say "everything's installed!"

    # Best-effort shell completions and man-page install. The helper is bundled
    # into dist archives via dist-workspace.toml `include`; failures must not
    # fail the binary install.
    if [ -f "$_src_dir/install-shell-assets.sh" ]; then
        sh "$_src_dir/install-shell-assets.sh" || true
    fi
'''
    if replacement in text:
        return
    if needle not in text:
        raise SystemExit(f"could not find shell installer insertion point in {path}")
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
    distrib = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("target/distrib")
    patch_shell_installer(distrib / "cockpit-cli-installer.sh")
    patch_homebrew_formula(distrib / "cockpit.rb")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
