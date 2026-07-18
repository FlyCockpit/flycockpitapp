//! Helper for the TUI's "Set up GitHub Copilot auth" affordance.
//!
//! The supported Copilot auth path is documented env vars (see
//! `src/providers/models_fetch.rs`). For users who already have GitHub's
//! `gh` CLI installed and logged in, the fastest setup is one line in
//! their shell rc: `export GH_TOKEN=$(gh auth token)`. This module
//! detects the shell, picks the right rc file + syntax, and appends the
//! line idempotently (a marker comment guards against double-writes).
//!
//! Pure logic — no TUI. The settings dialog calls into this module and
//! renders the confirm screen on top of it.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Marker comment we prepend to the export so we can detect prior
/// runs and skip a second append. Keep the literal stable — changing
/// it breaks idempotency for users who ran the older version.
pub const MARKER: &str = "# cockpit-cli: GitHub Copilot auth (GH_TOKEN export)";

/// Shells whose rc-file syntax we know how to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Zsh,
    Bash,
    Fish,
}

impl Shell {
    pub fn name(self) -> &'static str {
        match self {
            Shell::Zsh => "zsh",
            Shell::Bash => "bash",
            Shell::Fish => "fish",
        }
    }

    /// Filename relative to `$HOME` where we write the export.
    pub fn rc_filename(self) -> &'static str {
        match self {
            Shell::Zsh => ".zshrc",
            Shell::Bash => ".bashrc",
            Shell::Fish => ".config/fish/config.fish",
        }
    }

    /// The single shell-syntax line we append (no marker, no trailing
    /// newline). Bash and zsh share POSIX-style `export`; fish uses
    /// `set -x` and parenthesized command substitution.
    pub fn export_line(self) -> &'static str {
        match self {
            Shell::Zsh | Shell::Bash => "export GH_TOKEN=$(gh auth token)",
            Shell::Fish => "set -x GH_TOKEN (gh auth token)",
        }
    }
}

/// Pull the user's login shell from `$SHELL` and map it to a [`Shell`].
/// Returns `None` if `$SHELL` is unset or names an unsupported shell.
pub fn detect_shell() -> Option<Shell> {
    let shell = std::env::var("SHELL").ok()?;
    detect_shell_from(&shell)
}

/// Test-friendly variant of [`detect_shell`] that takes the `$SHELL`
/// value explicitly.
pub fn detect_shell_from(shell_path: &str) -> Option<Shell> {
    let basename = Path::new(shell_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match basename {
        "zsh" => Some(Shell::Zsh),
        "bash" => Some(Shell::Bash),
        "fish" => Some(Shell::Fish),
        _ => None,
    }
}

/// Resolve the absolute rc-file path for a given shell. Returns `None`
/// only if we can't locate `$HOME`.
pub fn rc_path(shell: Shell) -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(shell.rc_filename()))
}

/// The full block we append: a blank line, the marker, the export,
/// trailing newline. Exposed so the confirm screen can preview the
/// exact bytes about to be written.
pub fn append_block(shell: Shell) -> String {
    format!("\n{MARKER}\n{}\n", shell.export_line())
}

/// True if `path` already contains our marker — i.e. a previous setup
/// run wrote the export. Missing file is treated as "not configured".
pub fn rc_already_configured(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let body = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(body.contains(MARKER))
}

/// Append [`append_block`] to `path`. Creates the file (and parent
/// directory, for fish) if needed. Idempotent: if the marker is
/// already present, this is a no-op and returns `Ok(false)`. Returns
/// `Ok(true)` when a write actually happened.
pub fn append_to_rc(path: &Path, shell: Shell) -> Result<bool> {
    if rc_already_configured(path)? {
        return Ok(false);
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {} for append", path.display()))?;
    f.write_all(append_block(shell).as_bytes())
        .with_context(|| format!("writing to {}", path.display()))?;
    Ok(true)
}

/// Run `gh auth token` and return the trimmed token. Emits a
/// user-readable error if `gh` is missing or the user isn't logged in.
pub fn fetch_gh_token() -> Result<String> {
    let out = Command::new("gh")
        .args(["auth", "token"])
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "`gh` CLI not found. Install from https://cli.github.com, \
                 then run `gh auth login` and try again."
            ),
            _ => anyhow::anyhow!("invoking `gh auth token`: {e}"),
        })?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!(
            "`gh auth token` exited with {}: {}",
            out.status,
            stderr.trim()
        );
    }
    let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if token.is_empty() {
        bail!("`gh auth token` returned an empty token — run `gh auth login`");
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_shell_zsh_bash_fish() {
        assert_eq!(detect_shell_from("/bin/zsh"), Some(Shell::Zsh));
        assert_eq!(detect_shell_from("/usr/bin/zsh"), Some(Shell::Zsh));
        assert_eq!(detect_shell_from("/bin/bash"), Some(Shell::Bash));
        assert_eq!(
            detect_shell_from("/opt/homebrew/bin/fish"),
            Some(Shell::Fish)
        );
    }

    #[test]
    fn detect_shell_unknown_returns_none() {
        assert_eq!(detect_shell_from("/bin/tcsh"), None);
        assert_eq!(detect_shell_from("/usr/local/bin/nu"), None);
        assert_eq!(detect_shell_from(""), None);
    }

    #[test]
    fn export_line_syntax_per_shell() {
        assert_eq!(Shell::Zsh.export_line(), "export GH_TOKEN=$(gh auth token)");
        assert_eq!(
            Shell::Bash.export_line(),
            "export GH_TOKEN=$(gh auth token)"
        );
        assert_eq!(Shell::Fish.export_line(), "set -x GH_TOKEN (gh auth token)");
    }

    #[test]
    fn rc_filename_per_shell() {
        assert_eq!(Shell::Zsh.rc_filename(), ".zshrc");
        assert_eq!(Shell::Bash.rc_filename(), ".bashrc");
        assert_eq!(Shell::Fish.rc_filename(), ".config/fish/config.fish");
    }

    #[test]
    fn append_block_contains_marker_and_export() {
        let block = append_block(Shell::Zsh);
        assert!(block.contains(MARKER));
        assert!(block.contains("export GH_TOKEN=$(gh auth token)"));
        // Leading newline keeps the block visually separated from
        // whatever's already in the user's rc file.
        assert!(block.starts_with('\n'));
        assert!(block.ends_with('\n'));
    }

    #[test]
    fn append_to_rc_creates_file_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".zshrc");
        let first = append_to_rc(&path, Shell::Zsh).unwrap();
        assert!(first, "first append should write");
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains(MARKER));
        assert!(body.contains("export GH_TOKEN=$(gh auth token)"));

        let second = append_to_rc(&path, Shell::Zsh).unwrap();
        assert!(!second, "second append should detect marker and skip");
        let body2 = fs::read_to_string(&path).unwrap();
        assert_eq!(body, body2, "file should be unchanged on second call");
    }

    #[test]
    fn append_to_rc_preserves_existing_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".bashrc");
        fs::write(&path, "alias ll='ls -la'\n").unwrap();
        append_to_rc(&path, Shell::Bash).unwrap();
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.starts_with("alias ll='ls -la'\n"));
        assert!(body.contains(MARKER));
    }

    #[test]
    fn append_to_rc_creates_parent_dir_for_fish() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".config/fish/config.fish");
        assert!(!path.exists());
        let wrote = append_to_rc(&path, Shell::Fish).unwrap();
        assert!(wrote);
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("set -x GH_TOKEN (gh auth token)"));
    }

    #[test]
    fn rc_already_configured_returns_false_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".zshrc-does-not-exist");
        assert!(!rc_already_configured(&path).unwrap());
    }
}
