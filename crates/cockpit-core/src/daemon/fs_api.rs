use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use base64::Engine as _;
use ignore::Match;
use sha2::{Digest, Sha256};

use crate::daemon::principal::ClientPrincipal;
use crate::daemon::proto::{
    ErrorCode, ErrorPayload, FsEntry, FsEntryKind, FsReadKind, GitStatusEntry, Response,
};
use crate::daemon::server::DaemonContext;

const FS_LIST_ENTRY_CAP: usize = 1_000;
const FS_TEXT_READ_BYTE_CAP: usize = crate::tools::common::OUTPUT_BYTE_CAP;
const FS_BINARY_READ_BYTE_CAP: usize = 256 * 1024;
const REMOTE_FILE_AGENT: &str = "remote-project-files";

pub fn fs_list(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    project_root: &str,
    path: &str,
    show_hidden: bool,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let dir = resolve_existing_path(&root, path)?;
    if !dir.is_dir() {
        return Err(bad_request(format!("`{path}` is not a directory")));
    }

    let mut entries = Vec::new();
    let mut truncated = false;
    for entry in std::fs::read_dir(&dir).map_err(internal)? {
        let entry = entry.map_err(internal)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !show_hidden && name.starts_with('.') {
            continue;
        }
        if entries.len() >= FS_LIST_ENTRY_CAP {
            truncated = true;
            break;
        }
        entries.push(entry_to_wire(ctx, principal, &root, entry.path(), name)?);
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Response::FsList { entries, truncated })
}

pub fn fs_stat(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    project_root: &str,
    path: &str,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let resolved = resolve_existing_path(&root, path)?;
    let name = resolved
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    let entry = entry_to_wire(ctx, principal, &root, resolved, name)?;
    Ok(Response::FsStat { entry })
}

pub fn fs_read(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    project_root: &str,
    path: &str,
    wants_base64: bool,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let resolved = resolve_existing_path(&root, path)?;
    if resolved.is_dir() {
        return Err(bad_request(format!("`{path}` is a directory")));
    }
    ensure_read_allowed(ctx, principal, &root, &resolved)?;

    let bytes = std::fs::read(&resolved).map_err(internal)?;
    let hash = content_hash(&bytes);
    let binary = crate::tools::common::looks_binary(&bytes);
    let kind = read_kind_for_path(&resolved, binary);
    if binary || wants_base64 {
        if !wants_base64 && !matches!(kind, FsReadKind::Image) {
            return Ok(Response::FsRead {
                content: None,
                hash,
                truncated: bytes.len() > FS_BINARY_READ_BYTE_CAP,
                kind,
            });
        }
        let cap = FS_BINARY_READ_BYTE_CAP.min(bytes.len());
        let truncated = bytes.len() > cap;
        let content = base64::engine::general_purpose::STANDARD.encode(&bytes[..cap]);
        return Ok(Response::FsRead {
            content: Some(content),
            hash,
            truncated,
            kind,
        });
    }

    let text = String::from_utf8_lossy(&bytes).into_owned();
    let cap = crate::text::floor_char_boundary(&text, FS_TEXT_READ_BYTE_CAP.min(text.len()));
    let truncated = text.len() > cap;
    Ok(Response::FsRead {
        content: Some(text[..cap].to_string()),
        hash,
        truncated,
        kind: FsReadKind::Text,
    })
}

pub fn fs_write(
    ctx: &DaemonContext,
    project_root: &str,
    path: &str,
    content: &str,
    base_hash: Option<String>,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let target = resolve_for_write(&root, path)?;
    let locks = ctx.registry.locks();
    let _guard = locks
        .acquire_transient(&target, REMOTE_FILE_AGENT)
        .map_err(lock_conflict)?;

    let current = match std::fs::read(&target) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(internal(err)),
    };
    let current_hash = content_hash(&current);
    if let Some(expected) = base_hash.as_deref()
        && expected != current_hash
    {
        return Err(ErrorPayload {
            code: ErrorCode::HashMismatch,
            message: format!("file changed before write; current hash is {current_hash}"),
        });
    }

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(internal)?;
    }
    std::fs::write(&target, content.as_bytes()).map_err(internal)?;
    let hash = content_hash(content.as_bytes());
    Ok(Response::FsWrite { hash })
}

pub fn fs_create_dir(project_root: &str, path: &str) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let target = resolve_for_write(&root, path)?;
    std::fs::create_dir_all(&target).map_err(internal)?;
    Ok(Response::Ack)
}

pub fn fs_rename(
    ctx: &DaemonContext,
    project_root: &str,
    from_path: &str,
    to_path: &str,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let from = resolve_existing_path(&root, from_path)?;
    let to = resolve_for_write(&root, to_path)?;
    let locks = ctx.registry.locks();
    let _from_guard = locks
        .acquire_transient(&from, REMOTE_FILE_AGENT)
        .map_err(lock_conflict)?;
    let _to_guard = locks
        .acquire_transient(&to, REMOTE_FILE_AGENT)
        .map_err(lock_conflict)?;
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent).map_err(internal)?;
    }
    std::fs::rename(&from, &to).map_err(internal)?;
    Ok(Response::Ack)
}

pub fn fs_delete(
    ctx: &DaemonContext,
    project_root: &str,
    path: &str,
) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let target = resolve_existing_path(&root, path)?;
    let locks = ctx.registry.locks();
    let _guard = locks
        .acquire_transient(&target, REMOTE_FILE_AGENT)
        .map_err(lock_conflict)?;
    let meta = std::fs::symlink_metadata(&target).map_err(internal)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(&target).map_err(internal)?;
    } else {
        std::fs::remove_file(&target).map_err(internal)?;
    }
    Ok(Response::Ack)
}

pub fn git_status(project_root: &str) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let outcome = crate::git::run_git(&root, &["status", "--porcelain=v2"]).map_err(internal)?;
    if !outcome.success {
        return Err(bad_request(outcome.stderr.trim().to_string()));
    }
    let entries = outcome
        .stdout
        .lines()
        .map(|raw| GitStatusEntry {
            raw: raw.to_string(),
        })
        .collect();
    Ok(Response::GitStatus { entries })
}

pub fn git_diff_file(project_root: &str, path: &str) -> Result<Response, ErrorPayload> {
    let root = canonical_project_root(project_root)?;
    let resolved = resolve_existing_or_parent_path(&root, path)?;
    let rel = resolved
        .strip_prefix(&root)
        .map_err(|_| path_outside_root(path))?
        .to_string_lossy()
        .into_owned();
    let outcome = crate::git::run_git(&root, &["diff", "--", &rel]).map_err(internal)?;
    if !outcome.success {
        return Err(bad_request(outcome.stderr.trim().to_string()));
    }
    let cap = crate::text::floor_char_boundary(
        &outcome.stdout,
        FS_TEXT_READ_BYTE_CAP.min(outcome.stdout.len()),
    );
    Ok(Response::GitDiffFile {
        diff: outcome.stdout[..cap].to_string(),
        truncated: outcome.stdout.len() > cap,
    })
}

fn entry_to_wire(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    root: &Path,
    path: PathBuf,
    name: String,
) -> Result<FsEntry, ErrorPayload> {
    let meta = std::fs::symlink_metadata(&path).map_err(internal)?;
    let is_symlink = meta.file_type().is_symlink();
    let canonical = std::fs::canonicalize(&path).ok();
    let escapes_root = canonical.as_deref().is_none_or(|p| !p.starts_with(root));
    let gitignored = canonical
        .as_deref()
        .map(crate::gitignore::is_gitignored)
        .unwrap_or(false);
    let secret_blocked = canonical
        .as_deref()
        .map(|p| secret_blocked_for_sharee(ctx, principal, root, p))
        .transpose()?
        .unwrap_or(false);
    let kind = if is_symlink {
        FsEntryKind::Symlink
    } else if meta.is_dir() {
        FsEntryKind::Directory
    } else if meta.is_file() {
        FsEntryKind::File
    } else {
        FsEntryKind::Other
    };
    let rel = path
        .strip_prefix(root)
        .unwrap_or(&path)
        .to_string_lossy()
        .into_owned();
    let symlink_target = if is_symlink {
        std::fs::read_link(&path)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    } else {
        None
    };
    Ok(FsEntry {
        name,
        path: rel,
        kind,
        size: meta.len(),
        mtime_ms: meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis().min(i64::MAX as u128) as i64),
        gitignored,
        blocked: escapes_root || secret_blocked,
        symlink_target,
    })
}

fn read_kind_for_path(path: &Path, binary: bool) -> FsReadKind {
    if is_image_path(path) {
        FsReadKind::Image
    } else if binary {
        FsReadKind::Binary
    } else {
        FsReadKind::Text
    }
}

fn is_image_path(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .map(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp"
            )
        })
        .unwrap_or(false)
}

fn ensure_read_allowed(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    root: &Path,
    path: &Path,
) -> Result<(), ErrorPayload> {
    if secret_blocked_for_sharee(ctx, principal, root, path)? {
        return Err(ErrorPayload {
            code: ErrorCode::Authorization,
            message: "remote principal cannot read gitignored or dotenv-protected files".into(),
        });
    }
    Ok(())
}

fn secret_blocked_for_sharee(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    root: &Path,
    path: &Path,
) -> Result<bool, ErrorPayload> {
    if principal.is_owner() {
        return Ok(false);
    }
    Ok(crate::gitignore::is_gitignored(path) || dotenv_pattern_matches(ctx, root, path)?)
}

fn dotenv_pattern_matches(
    ctx: &DaemonContext,
    root: &Path,
    path: &Path,
) -> Result<bool, ErrorPayload> {
    let trust_policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, root)
        .map_err(internal)?;
    let cfg = ctx
        .config_source()
        .load_with_trust(root, &trust_policy)
        .map_err(internal)?
        .1
        .redact;
    if cfg
        .extra_dotenv_paths
        .iter()
        .any(|extra| std::fs::canonicalize(extra).ok().as_deref() == Some(path))
    {
        return Ok(true);
    }
    let matcher = crate::gitignore::build_allowlist_matcher(root, &cfg.dotenv_patterns);
    Ok(matches!(
        matcher.matched_path_or_any_parents(path, path.is_dir()),
        Match::Ignore(_)
    ))
}

fn canonical_project_root(project_root: &str) -> Result<PathBuf, ErrorPayload> {
    let root = Path::new(project_root);
    match std::fs::canonicalize(root) {
        Ok(path) if path.is_dir() => Ok(path),
        Ok(_) => Err(ErrorPayload {
            code: ErrorCode::RootMissing,
            message: format!("project root `{project_root}` is not a directory"),
        }),
        Err(e) => Err(ErrorPayload {
            code: ErrorCode::RootMissing,
            message: format!("project root `{project_root}` is unavailable: {e}"),
        }),
    }
}

fn resolve_existing_path(root: &Path, path: &str) -> Result<PathBuf, ErrorPayload> {
    let rel = clean_relative_path(path)?;
    let joined = root.join(rel);
    let canonical = std::fs::canonicalize(&joined)
        .map_err(|e| bad_request(format!("cannot access `{path}`: {e}")))?;
    if canonical.starts_with(root) {
        Ok(canonical)
    } else {
        Err(path_outside_root(path))
    }
}

fn resolve_existing_or_parent_path(root: &Path, path: &str) -> Result<PathBuf, ErrorPayload> {
    match resolve_existing_path(root, path) {
        Ok(path) => Ok(path),
        Err(_) => resolve_for_write(root, path),
    }
}

fn resolve_for_write(root: &Path, path: &str) -> Result<PathBuf, ErrorPayload> {
    let rel = clean_relative_path(path)?;
    if rel.as_os_str().is_empty() {
        return Err(bad_request("path must name a file or directory"));
    }
    let joined = root.join(&rel);
    match std::fs::symlink_metadata(&joined) {
        Ok(_) => return resolve_existing_path(root, path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(bad_request(format!("cannot access `{path}`: {err}"))),
    }
    let mut ancestor = joined
        .parent()
        .ok_or_else(|| bad_request("path has no parent directory"))?;
    while !ancestor.try_exists().map_err(internal)? {
        ancestor = ancestor
            .parent()
            .ok_or_else(|| bad_request(format!("parent for `{path}` is unavailable")))?;
    }
    let canonical_ancestor = std::fs::canonicalize(ancestor)
        .map_err(|e| bad_request(format!("parent for `{path}` is unavailable: {e}")))?;
    if !canonical_ancestor.starts_with(root) {
        return Err(path_outside_root(path));
    }
    Ok(root.join(rel))
}

fn clean_relative_path(path: &str) -> Result<PathBuf, ErrorPayload> {
    let input = Path::new(path);
    if input.is_absolute() {
        return Err(path_outside_root(path));
    }
    let mut out = PathBuf::new();
    for component in input.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => out.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(path_outside_root(path));
            }
        }
    }
    Ok(out)
}

fn content_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn path_outside_root(path: &str) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::PathOutsideRoot,
        message: format!("`{path}` resolves outside the project root"),
    }
}

fn lock_conflict(err: anyhow::Error) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::LockConflict,
        message: format!("{err:#}"),
    }
}

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: message.into(),
    }
}

fn internal<E: std::fmt::Display>(err: E) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("{err:#}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::principal::{
        ClientPrincipal, PrincipalGrant, PrincipalScope, RemotePrincipal,
    };

    fn test_ctx(root: &Path) -> crate::daemon::server::DaemonContext {
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        db.set_workspace_trust(root, crate::db::workspace_trust::WorkspaceTrustMode::Trust)
            .expect("trust root");
        let locks = std::sync::Arc::new(crate::locks::LockManager::from_db(db.clone()).unwrap());
        crate::daemon::server::DaemonContext::new(
            db,
            locks,
            crate::daemon::DaemonPaths {
                socket: PathBuf::from("/tmp/cockpit-fs-test.sock"),
                pid_file: PathBuf::from("/tmp/cockpit-fs-test.pid"),
                ephemeral: true,
            },
            crate::daemon::terminal::test_host_factory(),
            crate::daemon::config_source::ConfigSource::fixed(
                crate::config::providers::ProvidersConfig::default(),
                crate::config::extended::ExtendedConfig::default(),
            ),
        )
    }

    fn remote_project_files(root: &Path) -> ClientPrincipal {
        ClientPrincipal::Remote(RemotePrincipal {
            user_id: "user-1".into(),
            grants: vec![PrincipalGrant {
                scope: PrincipalScope::ProjectFiles,
                project_root: Some(root.to_string_lossy().into_owned()),
            }],
        })
    }

    #[test]
    fn rejects_traversal_absolute_and_prefix_collision() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        let sibling = tmp.path().join("app2");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(root.join("ok.txt"), "ok").unwrap();
        std::fs::write(sibling.join("secret.txt"), "no").unwrap();

        assert!(
            resolve_existing_path(&root.canonicalize().unwrap(), "../app2/secret.txt").is_err()
        );
        assert!(
            resolve_existing_path(
                &root.canonicalize().unwrap(),
                sibling.join("secret.txt").to_str().unwrap()
            )
            .is_err()
        );
        assert!(resolve_existing_path(&root.canonicalize().unwrap(), "ok.txt").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        let outside = tmp.path().join("outside.txt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&outside, "secret").unwrap();
        symlink(&outside, root.join("link.txt")).unwrap();

        let err = resolve_existing_path(&root.canonicalize().unwrap(), "link.txt").unwrap_err();
        assert_eq!(err.code, ErrorCode::PathOutsideRoot);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_dangling_symlink_for_write() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        let outside = tmp.path().join("missing.txt");
        std::fs::create_dir_all(&root).unwrap();
        symlink(&outside, root.join("link.txt")).unwrap();

        let err = resolve_for_write(&root.canonicalize().unwrap(), "link.txt").unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
    }

    #[test]
    fn dotenv_file_is_blocked_for_sharee_but_not_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let ctx = test_ctx(root);
        std::fs::write(root.join(".env"), "SECRET=value").unwrap();
        let path = root.join(".env").canonicalize().unwrap();
        assert!(secret_blocked_for_sharee(&ctx, &remote_project_files(root), root, &path).unwrap());
        assert!(!secret_blocked_for_sharee(&ctx, &ClientPrincipal::owner(), root, &path).unwrap());
    }

    #[test]
    fn gitignored_file_is_flagged_in_listing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let ctx = test_ctx(root);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::write(root.join(".gitignore"), "ignored.txt\n").unwrap();
        std::fs::write(root.join("ignored.txt"), "secret").unwrap();
        let Response::FsList { entries, .. } = fs_list(
            &ctx,
            &remote_project_files(root),
            root.to_str().unwrap(),
            ".",
            true,
        )
        .unwrap() else {
            panic!("expected fs list");
        };
        let ignored = entries
            .iter()
            .find(|entry| entry.name == "ignored.txt")
            .unwrap();
        assert!(ignored.gitignored);
        assert!(ignored.blocked);
    }
}
