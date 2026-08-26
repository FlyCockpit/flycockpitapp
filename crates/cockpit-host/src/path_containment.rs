//! Symlink-aware host path containment.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Return the syscall-effective path for `path`, resolving symlinks through the
/// nearest existing parent while preserving a nonexistent leaf. This lets new
/// files be checked against the same containment rule as existing files.
pub fn effective_path(path: &Path) -> std::io::Result<PathBuf> {
    let mut current = path;
    loop {
        match std::fs::canonicalize(current) {
            Ok(base) => return append_unresolved_tail(base, path, current),
            Err(err) => {
                if std::fs::symlink_metadata(current)
                    .map(|meta| meta.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    return Err(err);
                }
                let Some(parent) = current.parent() else {
                    return Err(err);
                };
                if parent == current {
                    return Err(err);
                }
                current = parent;
            }
        }
    }
}

fn append_unresolved_tail(
    mut base: PathBuf,
    original: &Path,
    existing_prefix: &Path,
) -> std::io::Result<PathBuf> {
    let tail = original
        .strip_prefix(existing_prefix)
        .unwrap_or_else(|_| Path::new(""));
    for component in tail.components() {
        match component {
            std::path::Component::Normal(part) => base.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unresolved parent traversal in `{}`", original.display()),
                ));
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
        }
    }
    if base.file_name() == Some(OsStr::new("..")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unresolved parent traversal in `{}`", original.display()),
        ));
    }
    Ok(base)
}

/// True when `candidate` is equal to or under `root` after symlink-aware
/// normalization. Nonexistent leaves are allowed when their existing parent is
/// contained.
pub fn contained_under(root: &Path, candidate: &Path) -> bool {
    let Ok(root) = effective_path(root) else {
        return false;
    };
    let Ok(candidate) = effective_path(candidate) else {
        return false;
    };
    candidate.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contained_under_symlink_and_prefix_semantics() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("root");
        let sibling = tmp.path().join("root-sibling");
        std::fs::create_dir_all(root.join("scope")).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();

        assert!(contained_under(&root, &root.join("scope/new.txt")));
        assert!(!contained_under(&root, &sibling.join("file.txt")));

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&sibling, root.join("scope/link")).unwrap();
            assert!(!contained_under(
                &root,
                &root.join("scope/link/escaped.txt")
            ));
        }
    }
}
