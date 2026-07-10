use super::*;

/// Resolve the directory cockpit clones Git packages into. Honors the
/// `packages_directory` config key (tilde-expanded), else
/// `~/src/cockpit-packages/`.
pub fn clone_dir(cwd: &Path) -> Result<PathBuf> {
    if let Some(dir) = configured_clone_dir(cwd) {
        return Ok(dir);
    }
    let home = dirs::home_dir().context("could not locate home dir")?;
    Ok(home.join(DEFAULT_CLONE_SUBDIR))
}

/// Read `packages_directory` from the first layered `config.json`
/// that sets it, tilde-expanded. `None` when unset.
fn configured_clone_dir(cwd: &Path) -> Option<PathBuf> {
    crate::config::extended::load_for_cwd(cwd)
        .packages_directory
        .map(|p| {
            let expanded = shellexpand::tilde(&p.to_string_lossy()).into_owned();
            PathBuf::from(expanded)
        })
}

/// Percent-encode an identifier for use as a directory name. Encodes
/// every byte that isn't an unreserved URL char (`A-Za-z0-9._-`), so
/// `npm:@tanstack/query` becomes a single flat, filesystem-safe segment
/// — matching kcl's clone-dir scheme.
pub fn percent_encode_identifier(identifier: &str) -> String {
    let mut out = String::with_capacity(identifier.len());
    for &b in identifier.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0xf));
        }
    }
    out
}

pub(super) fn encoded_identifier_segment(identifier: &str) -> Result<String> {
    let encoded = percent_encode_identifier(identifier);
    if encoded == "." || encoded == ".." {
        bail!(
            "invalid package identifier `{identifier}`: encoded clone directory segment `{encoded}` would escape the package clone directory"
        );
    }
    Ok(encoded)
}

pub(super) fn clone_destination(cwd: &Path, identifier: &str) -> Result<(PathBuf, PathBuf)> {
    let dir = clone_dir(cwd)?;
    let dest = clone_destination_in_dir(&dir, identifier)?;
    Ok((dir, dest))
}

pub(super) fn clone_destination_in_dir(dir: &Path, identifier: &str) -> Result<PathBuf> {
    let segment = encoded_identifier_segment(identifier)?;
    let dest = dir.join(segment);
    if !lexically_contains(dir, &dest) {
        bail!(
            "invalid package identifier `{identifier}`: clone destination `{}` escapes package clone directory `{}`",
            dest.display(),
            dir.display()
        );
    }
    Ok(dest)
}

pub(super) fn lexically_contains(base: &Path, candidate: &Path) -> bool {
    let base = lexical_normalize(base);
    let candidate = lexical_normalize(candidate);
    candidate.starts_with(&base) && candidate != base
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    HEX[nibble as usize] as char
}

/// Run `git clone`. Shallow (`--depth 1`) by default to bound disk/time
/// for large dependencies (prompt decision 4). A non-zero exit surfaces
/// the captured stderr as the error (clean failure, no panic).
pub(super) fn git_clone(url: &str, dest: &Path, branch: Option<&str>, shallow: bool) -> Result<()> {
    let mut cmd = build_git_clone_command(url, dest, branch, shallow);
    let output = cmd
        .output()
        .context("spawning `git clone` (is git installed and on PATH?)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git clone failed: {}", stderr.trim());
    }
    Ok(())
}

pub(super) fn build_git_clone_command(
    url: &str,
    dest: &Path,
    branch: Option<&str>,
    shallow: bool,
) -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("-c")
        .arg("protocol.ext.allow=never")
        .arg("-c")
        .arg("protocol.file.allow=never");
    cmd.arg("clone");
    if shallow {
        cmd.arg("--depth").arg("1").arg("--no-single-branch");
    }
    if let Some(b) = branch {
        cmd.arg("--branch").arg(b);
    }
    cmd.arg("--").arg(url).arg(dest);
    cmd
}
