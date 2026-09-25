use super::*;

/// Filenames in the SSH dir that are never private keys and are skipped
/// without reading their content: public keys, the known-hosts cache, the
/// authorized-keys list, and the SSH client `config`. The content check
/// alone already excludes these (none carries a PEM private-key header), but
/// skipping by name avoids reading files we know aren't keys.
fn is_ssh_non_key_name(name: &str) -> bool {
    name.ends_with(".pub")
        || name.starts_with("known_hosts")
        || name == "authorized_keys"
        || name == "config"
}

/// `true` when `content` begins (after leading whitespace) with a PEM
/// private-key header.
pub(super) fn is_pem_private_key(content: &str) -> bool {
    let trimmed = content.trim_start();
    PEM_PRIVATE_KEY_HEADERS
        .iter()
        .any(|h| trimmed.starts_with(h))
}

/// Resolve the SSH key directory a build in `scope` scans: the one resolver
/// shared by table capture and coverage bindings.
///
/// - Unset: the user's `~/.ssh`, which must resolve to an absolute path (a
///   relative `HOME` would otherwise be read relative to the process cwd).
///   No home directory means no SSH source.
/// - Absolute: used as written.
/// - Relative: anchored at the workspace root for a workspace scope; a
///   daemon-global build has no root and rejects it, as does any non-absolute
///   path with a root or Windows prefix.
pub(crate) fn resolve_ssh_key_dir(
    scope: RedactionSourceScope<'_>,
    configured: Option<&Path>,
) -> Result<Option<PathBuf>> {
    match configured {
        Some(dir) => {
            let base = match scope {
                RedactionSourceScope::Workspace(root) => Some(root),
                RedactionSourceScope::DaemonGlobal => None,
            };
            crate::config::extended::anchor_config_relative_path(base, dir)
                .map(Some)
                .ok_or_else(|| {
                    UnanchoredRedactionSourcePath {
                        setting: "redact.ssh_key_dir",
                        path: dir.to_path_buf(),
                    }
                    .into()
                })
        }
        None => match dirs::home_dir() {
            None => Ok(None),
            Some(home) if home.is_absolute() => Ok(Some(home.join(".ssh"))),
            Some(home) => Err(UnanchoredRedactionSourcePath {
                setting: "HOME",
                path: home,
            }
            .into()),
        },
    }
}

/// Collect `(value, origin)` candidates for every private SSH key under the
/// already-resolved `ssh_key_dir` (see [`resolve_ssh_key_dir`]); `None` means
/// there is no SSH source. A missing directory is an empty source; an
/// unreadable one fails closed. For each regular
/// file (symlinks followed to their target) whose content is a PEM private
/// key, the trimmed full key text is registered with origin `$ssh:<file>`;
/// a newline-normalized (`\r\n`→`\n`) variant is added when it differs so a
/// CRLF/LF echo both match. The caller treats these as forced/non-prunable.
pub(super) fn collect_ssh_key_candidates(
    ssh_key_dir: Option<&Path>,
) -> Result<Vec<(String, String)>> {
    collect_ssh_key_candidates_with_fence(ssh_key_dir, |_| {})
}

pub(super) fn collect_ssh_key_candidates_with_fence(
    ssh_key_dir: Option<&Path>,
    mut before_confirm: impl FnMut(&Path),
) -> Result<Vec<(String, String)>> {
    let Some(dir) = ssh_key_dir.map(Path::to_path_buf) else {
        return Ok(Vec::new());
    };

    let discover = || -> Result<Option<Vec<PathBuf>>> {
        let read_dir = match std::fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            // A configured directory may legitimately not exist yet. Absence
            // is a stable empty source view; unreadable existing directories
            // still fail closed because they may contain configured material.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "configured SSH source is unavailable during capture: {error}"
                ));
            }
        };
        let mut paths = read_dir
            .map(|entry| {
                entry.map(|entry| entry.path()).map_err(|error| {
                    anyhow::anyhow!("configured SSH source is unavailable during capture: {error}")
                })
            })
            .collect::<Result<Vec<PathBuf>>>()?;
        paths.sort();
        Ok(Some(paths))
    };
    let Some(discovered) = discover()? else {
        return Ok(Vec::new());
    };

    let mut out: Vec<(String, String)> = Vec::new();
    for path in &discovered {
        let Some(file_name) = path.file_name() else {
            continue;
        };
        let name = file_name.to_string_lossy();
        if is_ssh_non_key_name(&name) {
            continue;
        }
        // Only regular files (symlinks followed to their target: it is the
        // key *material* being redacted) can be keys. Sockets (ControlMaster),
        // FIFOs and directories are skipped, as is an entry that disappears
        // between listing and inspection: it contributes no key, and the
        // publication fence rereads the directory.
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "configured SSH source is unreadable during capture: {error}"
                ));
            }
        };
        if !meta.is_file() {
            continue;
        }
        let Some(content) = read_ssh_candidate(path)? else {
            continue;
        };
        if !is_pem_private_key(&content) {
            continue;
        }
        let target_before = std::fs::canonicalize(path).map_err(|error| {
            anyhow::anyhow!("configured SSH source is unreadable during capture: {error}")
        })?;
        before_confirm(path);
        // A configured symlink can be retargeted independently of the
        // directory entry. Capture refuses an unstable key read instead of
        // publishing coverage for either half of the replacement.
        let target_after = std::fs::canonicalize(path)
            .map_err(|_| anyhow::anyhow!("configured SSH source changed during capture"))?;
        let confirm = read_ssh_source_text(path)
            .map_err(|_| anyhow::anyhow!("configured SSH source changed during capture"))?;
        if target_before != target_after || content != confirm {
            anyhow::bail!("configured SSH source changed during capture");
        }
        let origin = format!("$ssh:{name}");
        let trimmed = content.trim().to_string();
        if !trimmed.is_empty() {
            let normalized = trimmed.replace("\r\n", "\n");
            if normalized != trimmed {
                out.push((normalized.clone(), origin.clone()));
            }
            for line in normalized
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
            {
                out.push((line.to_string(), origin.clone()));
            }
            out.push((trimmed, origin));
        }
    }
    // No listing-equality check: churn of non-key entries (ControlMaster
    // sockets, editor temp files) must not fail capture. A key appearing or
    // changing after this pass changes the fresh-read source binding, so the
    // coverage authority refuses to publish this table (key probe vs. the
    // captured-bytes boundary, and the publication fence).
    Ok(out)
}

/// Read one directory entry as a possible key. `Ok(None)` for an entry that
/// cannot be a key: it disappeared, is no longer a regular file, is larger
/// than any key, or is not UTF-8 (`.DS_Store` and other binary files). Any
/// other failure (for example permission denied) is an error: the entry could
/// be key material that coverage would silently miss.
fn read_ssh_candidate(path: &Path) -> Result<Option<String>> {
    use crate::resource_limits::ResourceLimitError;
    match crate::resource_limits::read_for_tool(path) {
        Ok(bytes) => Ok(String::from_utf8(bytes).ok()),
        Err(error) if error.is_not_found() => Ok(None),
        Err(ResourceLimitError::ByteLimit { .. }) => Ok(None),
        Err(ResourceLimitError::Io(cockpit_host::bounded::BoundedIoError::NotRegular {
            ..
        })) => Ok(None),
        Err(error) => Err(anyhow::anyhow!(
            "configured SSH source is unreadable during capture: {error}"
        )),
    }
}

pub(super) fn read_ssh_source_text(path: &Path) -> Result<String> {
    let bytes = crate::resource_limits::read_for_tool(path)?;
    String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("SSH source is not UTF-8"))
}
