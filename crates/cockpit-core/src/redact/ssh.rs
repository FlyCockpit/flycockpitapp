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

/// The SSH key directory a build scans, and whether the user configured it.
///
/// The distinction decides what absence means: only the *unconfigured*
/// default (`~/.ssh`) may be absent (lstat NotFound), which is an empty
/// source. A configured directory that is missing, a dangling link, or
/// otherwise unreadable is an unavailable source and fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshKeyDir {
    pub(crate) path: PathBuf,
    pub(crate) configured: bool,
}

impl SshKeyDir {
    pub(crate) fn configured(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            configured: true,
        }
    }

    pub(crate) fn default_dir(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            configured: false,
        }
    }
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
) -> Result<Option<SshKeyDir>> {
    match configured {
        Some(dir) => {
            let base = match scope {
                RedactionSourceScope::Workspace(root) => Some(root),
                RedactionSourceScope::DaemonGlobal => None,
            };
            crate::config::extended::anchor_config_relative_path(base, dir)
                .map(|path| Some(SshKeyDir::configured(path)))
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
            Some(home) if home.is_absolute() => Ok(Some(SshKeyDir::default_dir(home.join(".ssh")))),
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
/// there is no SSH source. Only an absent *default* directory is an empty
/// source; a configured directory that is missing or dangling, and any
/// unreadable directory, fail closed. For each regular
/// file (symlinks followed to their target) whose content is a PEM private
/// key, the trimmed full key text is registered with origin `$ssh:<file>`;
/// a newline-normalized (`\r\n`→`\n`) variant is added when it differs so a
/// CRLF/LF echo both match. The caller treats these as forced/non-prunable.
pub(super) fn collect_ssh_key_candidates(
    ssh_key_dir: Option<&SshKeyDir>,
) -> Result<Vec<(String, String)>> {
    collect_ssh_key_candidates_with_fence(ssh_key_dir, |_| {})
}

/// List the directory's entries, sorted. `Ok(None)` only for an absent
/// unconfigured default directory.
fn list_ssh_key_dir(dir: &SshKeyDir) -> Result<Option<Vec<PathBuf>>> {
    let read_dir = match std::fs::read_dir(&dir.path) {
        Ok(read_dir) => read_dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // `read_dir` also reports NotFound through a dangling link. Only
            // the default directory may be absent, and only when lstat
            // agrees that nothing is there.
            let absent = matches!(
                std::fs::symlink_metadata(&dir.path),
                Err(ref lstat) if lstat.kind() == std::io::ErrorKind::NotFound
            );
            if absent && !dir.configured {
                return Ok(None);
            }
            return Err(anyhow::anyhow!(
                "configured SSH source is unavailable during capture: {}",
                if absent {
                    "the configured redact.ssh_key_dir does not exist"
                } else {
                    "the SSH key directory is a dangling link"
                }
            ));
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
}

/// Whether `path` is, right now, a private key the collector would register.
fn is_ssh_key_entry(path: &Path) -> Result<bool> {
    let Some(name) = path.file_name() else {
        return Ok(false);
    };
    if is_ssh_non_key_name(&name.to_string_lossy()) {
        return Ok(false);
    }
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "configured SSH source is unreadable during capture: {error}"
            ));
        }
    }
    Ok(read_ssh_candidate(path)?.is_some_and(|content| is_pem_private_key(&content)))
}

pub(super) fn collect_ssh_key_candidates_with_fence(
    ssh_key_dir: Option<&SshKeyDir>,
    mut before_confirm: impl FnMut(&Path),
) -> Result<Vec<(String, String)>> {
    let Some(dir) = ssh_key_dir else {
        return Ok(Vec::new());
    };
    let Some(discovered) = list_ssh_key_dir(dir)? else {
        return Ok(Vec::new());
    };

    let mut out: Vec<(String, String)> = Vec::new();
    let mut collected = std::collections::BTreeSet::new();
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
        // between listing and inspection: it contributes no key.
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
        collected.insert(path.clone());
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
    // Source-set closure: every key in the directory *now* must be one this
    // pass collected. Re-enumerate after confirming and refuse if a key
    // appeared (or a non-key entry became one) while the pass ran — this
    // collector is also the publication fence, so a key added during the
    // fence would otherwise go uncovered. Churn of non-key entries
    // (ControlMaster sockets, editor temp files) and removed entries are
    // tolerated: they add no uncovered key.
    let Some(after) = list_ssh_key_dir(dir)? else {
        anyhow::bail!("configured SSH source changed during capture");
    };
    for path in after.iter().filter(|path| !collected.contains(*path)) {
        if is_ssh_key_entry(path)? {
            anyhow::bail!("configured SSH source changed during capture: a key was added");
        }
    }
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
